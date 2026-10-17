"""Primary-email change of a verified account (ADR-011, ADR-015, ADR-016, Backend#35).

``requestPrimaryEmailChange`` stores a pending change for the new address, supersedes any earlier one and
queues the bearer email to the new address; the current address stays in effect. ``verifyPrimaryEmailChange``
consumes the bearer in the session that requested the change and, in one transaction, makes the new address
the account's verified primary email, rotates that session, revokes every other session of the account
(allauth ``email_changed``, wired in ``signals.py``) and queues a security notice to the previous address,
which is submitted only after that commit (ADR-015). Both run only for a recently authenticated session
(``sessions.recently_authenticated``), which the views check.

The bearer authorizes completing the change and nothing else: it never logs anyone in, and its plaintext
exists only in memory, in the email's URI fragment and in the request body. This lifecycle never accepts
an initial-verification bearer, nor ``verifyEmail`` a change bearer: they live in different tables.
"""

from __future__ import annotations

import datetime
import secrets
from dataclasses import dataclass

from allauth.account import signals as account_signals
from allauth.account.models import EmailAddress
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from psycopg import errors as pg_errors

from apps.api.errors import Conflict
from apps.email_delivery.adapter import EmailMessage
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.service import queue_email

from .models import EmailVerificationBearer, PrimaryEmailChange, User
from .sessions import session_binding
from .verification import BEARER_BYTES, bearer_digest, lock_account

DELIVERY_TEMPLATE = "primary-email-change"
DELIVERY_SUBJECT_TYPE = "primary-email-change"
NOTICE_TEMPLATE = "primary-email-changed"


class EmailChangeConflict(Conflict):
    default_detail = "The address is current, already used, or incompatible with the account state."


class NoCompatibleEmailChange(Conflict):
    """409 for every bearer that cannot complete a change here: one response for all of them (ADR-016)."""

    default_detail = "No compatible pending primary-email change can be completed."


@dataclass(frozen=True)
class RequestedChange:
    change: PrimaryEmailChange
    delivery: EmailDelivery


def change_link(request, bearer: str) -> str:
    """Same-origin frontend link carrying the bearer only in the fragment, never in a path or query."""
    return f"{request.build_absolute_uri(settings.FRONTEND_PRIMARY_EMAIL_CHANGE_PATH)}#verifier={bearer}"


def _message(to: str, link: str) -> EmailMessage:
    minutes = settings.AUTH_PRIMARY_EMAIL_CHANGE_LIFETIME_SECONDS // 60
    return EmailMessage(
        to=to,
        subject="Confirm your new HouseHoldHub email address",
        text_body=(
            "Confirm the new email address of your HouseHoldHub account by opening this link within "
            f"{minutes} minutes, in the browser where you requested the change:\n\n"
            f"{link}\n\n"
            "Your current address stays in use until you confirm. If you did not request this change, "
            "you can ignore this email."
        ),
    )


def _notice(to: str) -> EmailMessage:
    """Security notice to the address an account just left. No link, bearer or new address."""
    return EmailMessage(
        to=to,
        subject="The email address of your HouseHoldHub account was changed",
        text_body=(
            "The email address of the HouseHoldHub account that used this address was just changed. This "
            "address no longer signs in to that account, and every other signed-in session was signed out.\n\n"
            "If you made this change, no action is needed. If you did not, someone else may control your "
            "account: contact the HouseHoldHub operators."
        ),
    )


def _address_taken(email: str, user: User) -> bool:
    """Whether another account holds ``email``, as its login identity or as any allauth address."""
    return (
        User.objects.filter(email=email).exclude(pk=user.pk).exists()
        or EmailAddress.objects.filter(email__iexact=email).exclude(user_id=user.pk).exists()
    )


def request_primary_email_change(request, user: User, new_email: str) -> RequestedChange:
    """Supersede the account's usable change, store a new one and queue its email after the commit.

    ``new_email`` is normalized. Must run inside the domain transaction (``queue_email`` refuses otherwise).
    Raises ``EmailChangeConflict`` when the address is the current one, belongs to another account, or the
    account is not in a state that can change its email. The change is bound to the requesting session by
    its keyed digest, written with the row under the account lock: concurrent requests of one session leave
    the binding on the change that superseded the others, whatever order they answer in.
    """
    binding = session_binding(request)
    account = lock_account(user.pk)
    if binding is None or account is None or not account.is_active or not account.is_email_verified:
        raise EmailChangeConflict()
    if new_email == account.email or _address_taken(new_email, account):
        raise EmailChangeConflict()
    now = timezone.now()
    PrimaryEmailChange.objects.filter(user=account, superseded_at__isnull=True, consumed_at__isnull=True).update(
        superseded_at=now
    )
    bearer = secrets.token_urlsafe(BEARER_BYTES)
    change = PrimaryEmailChange.objects.create(
        user=account,
        new_email=new_email,
        digest=bearer_digest(bearer),
        session_binding=binding,
        expires_at=now + datetime.timedelta(seconds=settings.AUTH_PRIMARY_EMAIL_CHANGE_LIFETIME_SECONDS),
    )
    delivery = queue_email(
        _message(new_email, change_link(request, bearer)),
        template=DELIVERY_TEMPLATE,
        subject_type=DELIVERY_SUBJECT_TYPE,
        subject_id=change.pk,
    )
    return RequestedChange(change=change, delivery=delivery)


def complete_primary_email_change(request, user: User, bearer: str) -> None:
    """Consume the bearer and establish the new primary address, rotating and revoking sessions, atomically.

    The bearer must belong to ``user``, be usable, and have been requested by this session (its
    ``session_binding``). Anything else, or an address another account took meanwhile, raises
    ``NoCompatibleEmailChange`` and changes nothing. The previous address is notified only once the change
    has committed: a rollback discards the notice with everything else.
    """
    digest = bearer_digest(bearer)
    binding = session_binding(request)
    try:
        with transaction.atomic():
            account = lock_account(user.pk)
            change = PrimaryEmailChange.objects.select_for_update().filter(digest=digest, user_id=user.pk).first()
            now = timezone.now()
            if (
                account is None
                or not account.is_active
                or change is None
                or not change.is_usable(now)
                or binding is None
                or not constant_time_compare(binding, change.session_binding)
                or _address_taken(change.new_email, account)
            ):
                raise NoCompatibleEmailChange()
            change.consumed_at = now
            change.save(update_fields=["consumed_at"])

            previous_email = account.email
            previous = EmailAddress.objects.filter(user=account, email=previous_email).first()
            # The new address replaces every allauth address of the account: one verified primary row,
            # and the old address is released rather than kept as a second identity.
            EmailAddress.objects.filter(user=account).delete()
            account.email = change.new_email
            account.save(update_fields=["email"])
            current = EmailAddress.objects.create(user=account, email=account.email, primary=True, verified=True)
            EmailVerificationBearer.objects.filter(
                user=account, superseded_at__isnull=True, consumed_at__isnull=True
            ).update(superseded_at=now)
            # ADR-015: recorded in this transaction, submitted after its commit, never for a rollback.
            queue_email(
                _notice(previous_email),
                template=NOTICE_TEMPLATE,
                subject_type=DELIVERY_SUBJECT_TYPE,
                subject_id=change.pk,
            )
            # Revocation matrix (ADR-011): rotate this session and revoke all others, inside this
            # transaction so the change never commits with the other sessions still valid.
            account_signals.email_changed.send(
                sender=User, request=request, user=account, from_email_address=previous, to_email_address=current
            )
    except IntegrityError as exc:
        # A concurrent signup or change took the address between the check and the write.
        if isinstance(exc.__cause__, pg_errors.UniqueViolation):
            raise NoCompatibleEmailChange() from exc
        raise

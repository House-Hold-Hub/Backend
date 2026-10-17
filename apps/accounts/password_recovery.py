"""Password recovery and authenticated password change (ADR-011, ADR-015, ADR-016, security model, Backend#36).

``requestPasswordReset`` issues, ``resetPassword`` consumes; ``changePassword`` is the authenticated change.

- The reset bearer is 256 bits from the CSPRNG, stored only as its SHA-256 digest, valid for
  ``AUTH_PASSWORD_RESET_LIFETIME_SECONDS`` (1 hour) and mailed only in a frontend URI fragment. Issuing a new one
  supersedes the previous one; a reset or a password change supersedes it too. Consuming it is atomic with the
  password change: account row lock first, then the bearer row lock (the order of ``verification.py``), so
  concurrent attempts with one bearer see it consumed by exactly one of them.
- A reset request is enumeration-safe: it does the same observable work for every syntactically valid
  address. Accounts that cannot reset a password (unknown, disabled, or with no usable password such as a
  Google-only account) are skipped silently. The provider call of an existing account never runs inside the
  request (``DeferredSubmissions``), and the view pads the response to a fixed minimum duration.
- A reset ends every session of the account (allauth ``password_reset``, ``signals.on_password_reset``) inside the
  consuming transaction, under the account lock that session writes also take. A session created concurrently
  from the old credentials carries the old authentication hash and is flushed on its next request.
- A change verifies the current password, applies the new one under the account lock and rotates the current
  session while revoking the others (allauth ``password_changed``, ``signals.on_password_changed``).
"""

from __future__ import annotations

import datetime
import secrets
import time

from allauth.account import signals as allauth_signals
from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import NotAuthenticated

from apps.api.errors import Conflict
from apps.email_delivery.adapter import EmailMessage
from apps.email_delivery.service import DeferredSubmissions, queue_email

from .models import PasswordResetBearer, User
from .verification import BEARER_BYTES, bearer_digest, lock_account

DELIVERY_TEMPLATE = "password-reset"
DELIVERY_SUBJECT_TYPE = "password-reset-bearer"


class InvalidResetVerifier(serializers.ValidationError):
    """400 for every unusable bearer: unknown, expired, consumed, superseded, or for another address (ADR-016)."""

    def __init__(self):
        super().__init__({"verifier": ["The verifier is invalid or has expired."]})


class PasswordResetUnavailable(Conflict):
    default_detail = "The account has no password that can be reset."


class PasswordNotSet(Conflict):
    default_detail = "The account has no current password."


def _incorrect_current_password():
    return serializers.ValidationError({"current_password": ["The current password is incorrect."]})


def validate_new_password(password: str, user: User | None = None) -> None:
    """The ADR-016 policy (length, common passwords and, given the account, similarity) as a field error."""
    try:
        password_validation.validate_password(password, user)
    except DjangoValidationError as exc:
        raise serializers.ValidationError({"new_password": list(exc.messages)}) from exc


def _supersede_usable_bearers(user_id, now) -> None:
    PasswordResetBearer.objects.filter(user_id=user_id, superseded_at__isnull=True, consumed_at__isnull=True).update(
        superseded_at=now
    )


# ---- requestPasswordReset ----------------------------------------------------------------------------


def password_reset_link(request, bearer: str) -> str:
    """Same-origin frontend link carrying the bearer only in the fragment, never in a path or query."""
    return f"{request.build_absolute_uri(settings.FRONTEND_PASSWORD_RESET_PATH)}#verifier={bearer}"


def _reset_message(to: str, link: str) -> EmailMessage:
    minutes = settings.AUTH_PASSWORD_RESET_LIFETIME_SECONDS // 60
    return EmailMessage(
        to=to,
        subject="Reset your HouseHoldHub password",
        text_body=(
            f"Choose a new HouseHoldHub password by opening this link within {minutes} minutes:\n\n"
            f"{link}\n\n"
            "If you did not ask to reset your password, you can ignore this email: your password stays as it is."
        ),
    )


def request_password_reset(request, email: str, defer: DeferredSubmissions) -> None:
    """Issue a reset bearer and queue its email for an eligible account; do nothing for any other address.

    Never reports which case applied. Runs its own transaction, so the email is queued (into ``defer``) only
    once the bearer is committed.
    """
    user = User.objects.filter(email=email).first()
    if user is None or not user.is_active or not user.has_usable_password():
        return
    with transaction.atomic():
        account = lock_account(user.pk)  # serializes issuance and consumption per account
        if account is None or not account.is_active or not account.has_usable_password():
            return
        now = timezone.now()
        _supersede_usable_bearers(account.pk, now)
        bearer = secrets.token_urlsafe(BEARER_BYTES)
        record = PasswordResetBearer.objects.create(
            user=account,
            email=account.email,
            digest=bearer_digest(bearer),
            expires_at=now + datetime.timedelta(seconds=settings.AUTH_PASSWORD_RESET_LIFETIME_SECONDS),
        )
        queue_email(
            _reset_message(account.email, password_reset_link(request, bearer)),
            template=DELIVERY_TEMPLATE,
            subject_type=DELIVERY_SUBJECT_TYPE,
            subject_id=record.pk,
            defer=defer,
        )


def pad_response(started: float) -> None:
    """Sleep until ``AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS`` have passed since ``started`` (``time.monotonic``)."""
    remaining = started + settings.AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)


# ---- resetPassword -----------------------------------------------------------------------------------


def reset_password(request, bearer: str, new_password: str) -> None:
    """Consume a reset bearer and set the account's new password, revoking every session, atomically.

    Raises ``InvalidResetVerifier`` for any unusable bearer (and for a disabled account), a field error for a
    password that fails the policy for this account, and ``PasswordResetUnavailable`` when the account has no
    usable password; in every case nothing changes and the bearer stays usable (a policy failure is retryable).
    """
    digest = bearer_digest(bearer)
    record = PasswordResetBearer.objects.select_related("user").filter(digest=digest).first()
    if record is None or not record.is_usable(timezone.now()) or record.email != record.user.email:
        raise InvalidResetVerifier()
    user_id = record.user_id
    validate_new_password(new_password, record.user)
    hashed = make_password(new_password)  # the slow hash runs before the account lock is taken

    with transaction.atomic():
        account = lock_account(user_id)
        record = PasswordResetBearer.objects.select_for_update().filter(digest=digest, user_id=user_id).first()
        now = timezone.now()
        if (
            account is None
            or not account.is_active
            or record is None
            or not record.is_usable(now)
            or record.email != account.email
        ):
            raise InvalidResetVerifier()
        if not account.has_usable_password():
            raise PasswordResetUnavailable()
        record.consumed_at = now
        record.save(update_fields=["consumed_at"])
        account.password = hashed
        account.save(update_fields=["password"])
        # Revokes every session of the account, the request's own included.
        allauth_signals.password_reset.send(sender=User, request=request, user=account)


# ---- changePassword ----------------------------------------------------------------------------------


def change_password(request, user: User, current_password: str, new_password: str) -> None:
    """Verify the current password and replace it, rotating the current session and revoking all others.

    409 ``PasswordNotSet`` for an account with no usable password; 400 field errors for a wrong current
    password or a new one that fails the policy. A concurrent change that lands first makes this one's
    current password stale: it is then verified again against the stored hash and refused if it no longer matches.
    """
    account = User.objects.get(pk=user.pk)
    if not account.has_usable_password():
        raise PasswordNotSet()
    seen = account.password
    # check_password without a setter: it never rewrites the stored hash outside the account lock.
    if not check_password(current_password, seen):
        raise _incorrect_current_password()
    validate_new_password(new_password, account)
    hashed = make_password(new_password)  # the slow hash runs before the account lock is taken

    with transaction.atomic():
        locked = lock_account(account.pk)
        if locked is None or not locked.is_active:
            raise NotAuthenticated()  # disabled or deleted while this request ran
        if locked.password != seen and not check_password(current_password, locked.password):
            raise _incorrect_current_password()
        if not locked.has_usable_password():
            raise PasswordNotSet()
        locked.password = hashed
        locked.save(update_fields=["password"])
        _supersede_usable_bearers(locked.pk, timezone.now())  # a reset link requested earlier is void
        allauth_signals.password_changed.send(sender=User, request=request, user=locked)

"""Initial email verification: issuing bearers and their email, and consuming them (ADR-011, ADR-015, ADR-016).

Signup and ``resendEmailVerification`` issue; ``verifyEmail`` consumes. The plaintext bearer exists only in
memory, in the email's URI fragment and in the ``verifyEmail`` request body: the database keeps its SHA-256
digest, and the delivery record keeps no recipient, link or body. Consuming a bearer verifies the account's
email and nothing else: it never creates or authenticates a session (the view may only rotate the matching
restricted session of the same browser). The primary-email change of a verified account is a separate
lifecycle with its own bearers (``email_change.py``).
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
from dataclasses import dataclass

from allauth.account.models import EmailAddress
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers

from apps.api.errors import Conflict
from apps.email_delivery.adapter import EmailMessage
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.service import queue_email

from .models import EmailVerificationBearer, User

DELIVERY_TEMPLATE = "email-verification"
DELIVERY_SUBJECT_TYPE = "email-verification-bearer"
BEARER_BYTES = 32  # 256 bits from the operating system's CSPRNG


def bearer_digest(bearer: str) -> str:
    """The stored form of a bearer; bearers are looked up by this digest only."""
    return hashlib.sha256(bearer.encode("utf-8")).hexdigest()


class InvalidVerifier(serializers.ValidationError):
    """400 for every unusable bearer: unknown, expired, consumed, superseded or for another address (ADR-016)."""

    def __init__(self):
        super().__init__({"verifier": ["The verifier is invalid or has expired."]})


class EmailAlreadyVerified(Conflict):
    default_detail = "The email address is already verified."


@dataclass(frozen=True)
class IssuedVerification:
    bearer: EmailVerificationBearer
    delivery: EmailDelivery


def verification_link(request, bearer: str) -> str:
    """Same-origin frontend link carrying the bearer only in the fragment, never in a path or query."""
    return f"{request.build_absolute_uri(settings.FRONTEND_EMAIL_VERIFICATION_PATH)}#verifier={bearer}"


def _message(to: str, link: str) -> EmailMessage:
    hours = settings.AUTH_EMAIL_VERIFICATION_LIFETIME_SECONDS // 3600
    return EmailMessage(
        to=to,
        subject="Confirm your HouseHoldHub email address",
        text_body=(
            f"Confirm the email address of your HouseHoldHub account by opening this link within {hours} hours:\n\n"
            f"{link}\n\n"
            "If you did not create a HouseHoldHub account, you can ignore this email."
        ),
    )


def lock_account(user_id) -> User | None:
    """Lock the user row (``FOR NO KEY UPDATE``) for the rest of the transaction, as the session registry does.

    Every issuance and consumption of an account's bearers takes this lock first, so they serialize per
    account and always lock in the same order (account, then bearer).
    """
    return User.objects.select_for_update(no_key=True).filter(pk=user_id).first()


def issue_email_verification(request, user: User) -> IssuedVerification:
    """Supersede the account's usable bearer, store a new one and queue its email after the commit.

    Must run inside the domain transaction (``queue_email`` refuses otherwise), so a rollback discards
    the bearer and the delivery together and nothing is sent.
    """
    now = timezone.now()
    # Serialize issuance per account so the one-usable-bearer rule cannot race.
    lock_account(user.pk)
    EmailVerificationBearer.objects.filter(user=user, superseded_at__isnull=True, consumed_at__isnull=True).update(
        superseded_at=now
    )
    bearer = secrets.token_urlsafe(BEARER_BYTES)
    record = EmailVerificationBearer.objects.create(
        user=user,
        email=user.email,
        digest=bearer_digest(bearer),
        expires_at=now + datetime.timedelta(seconds=settings.AUTH_EMAIL_VERIFICATION_LIFETIME_SECONDS),
    )
    delivery = queue_email(
        _message(user.email, verification_link(request, bearer)),
        template=DELIVERY_TEMPLATE,
        subject_type=DELIVERY_SUBJECT_TYPE,
        subject_id=record.pk,
    )
    return IssuedVerification(bearer=record, delivery=delivery)


def verify_initial_email(bearer: str) -> User:
    """Consume an initial-verification bearer and mark the account's email verified, atomically.

    Raises ``InvalidVerifier`` for any unusable bearer (and for a disabled account) and
    ``EmailAlreadyVerified`` when the account's email is verified already; either way nothing changes.
    Concurrent requests with one bearer serialize on the account and bearer locks, so exactly one
    consumes it and the others see it consumed.
    """
    digest = bearer_digest(bearer)
    user_id = EmailVerificationBearer.objects.filter(digest=digest).values_list("user_id", flat=True).first()
    if user_id is None:
        raise InvalidVerifier()
    with transaction.atomic():
        user = lock_account(user_id)
        record = EmailVerificationBearer.objects.select_for_update().filter(digest=digest, user_id=user_id).first()
        now = timezone.now()
        if user is None or not user.is_active or record is None or not record.is_usable(now) or record.email != user.email:
            raise InvalidVerifier()
        if user.is_email_verified:
            raise EmailAlreadyVerified()
        record.consumed_at = now
        record.save(update_fields=["consumed_at"])
        # The canonical verified-email record is allauth's (ADR-011): exactly one primary, verified row
        # for the account's current address.
        EmailAddress.objects.filter(user=user).exclude(email=user.email).update(primary=False)
        EmailAddress.objects.update_or_create(user=user, email=user.email, defaults={"verified": True, "primary": True})
    return user

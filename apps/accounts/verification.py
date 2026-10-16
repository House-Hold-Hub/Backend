"""Issuing initial email-verification bearers and their email (ADR-016, ADR-015).

Only issuance lives here (signup needs it); verifying and resending are Backend#35. The plaintext bearer
exists only in memory and in the email's URI fragment: the database keeps its SHA-256 digest, and the
delivery record keeps no recipient, link or body.
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
from dataclasses import dataclass

from django.conf import settings
from django.utils import timezone

from apps.email_delivery.adapter import EmailMessage
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.service import queue_email

from .models import EmailVerificationBearer, User

DELIVERY_TEMPLATE = "email-verification"
DELIVERY_SUBJECT_TYPE = "email-verification-bearer"
BEARER_BYTES = 32  # 256 bits from the operating system's CSPRNG


def bearer_digest(bearer: str) -> str:
    """The stored form of a bearer; Backend#35 looks bearers up by this digest."""
    return hashlib.sha256(bearer.encode("utf-8")).hexdigest()


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


def issue_email_verification(request, user: User) -> IssuedVerification:
    """Supersede the account's usable bearer, store a new one and queue its email after the commit.

    Must run inside the domain transaction (``queue_email`` refuses otherwise), so a rollback discards
    the bearer and the delivery together and nothing is sent.
    """
    now = timezone.now()
    # Serialize issuance per account so the one-usable-bearer rule cannot race.
    User.objects.select_for_update(no_key=True).filter(pk=user.pk).first()
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

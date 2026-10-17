"""Request and response bodies of the authentication operations (Documentation ``api/openapi.yaml``)."""

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from apps.api.serializers import StrictCharField, StrictEmailField, StrictSerializer
from apps.email_delivery.models import EmailDelivery

from .models import User


class SignupSerializer(StrictSerializer):
    """``SignupRequest``. The email is normalized; the password is validated against ADR-016 as entered."""

    email = StrictEmailField(max_length=254)
    # Passwords are never trimmed or otherwise rewritten (ADR-016: accepted as entered).
    password = StrictCharField(trim_whitespace=False, write_only=True)
    name = StrictCharField(max_length=150)

    def validate_email(self, value):
        return User.objects.normalize_email(value)

    def validate(self, attrs):
        # The candidate user lets the similarity validator compare the password with the email and name.
        candidate = User(email=attrs["email"], name=attrs["name"])
        try:
            password_validation.validate_password(attrs["password"], candidate)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)}) from exc
        return attrs


class LoginSerializer(StrictSerializer):
    """``LoginRequest``. No length bounds on the password, so a policy change never locks a credential out."""

    email = StrictEmailField(max_length=254)
    password = StrictCharField(trim_whitespace=False, write_only=True)

    def validate_email(self, value):
        return User.objects.normalize_email(value)


class VerifierSerializer(StrictSerializer):
    """``EmailVerificationRequest``. The bearer is only hashed: never trimmed, echoed, stored or logged."""

    verifier = StrictCharField(trim_whitespace=False, write_only=True)


class PrimaryEmailChangeSerializer(StrictSerializer):
    """``PrimaryEmailChangeRequest``. The new address is normalized like every account email."""

    new_email = StrictEmailField(max_length=254)

    def validate_new_email(self, value):
        return User.objects.normalize_email(value)


def user_response(user: User) -> dict:
    """``UserResponse``."""
    return {
        "id": str(user.pk),
        "email": user.email,
        "name": user.name,
        "email_verified": user.is_email_verified,
        "google_linked": SocialAccount.objects.filter(user_id=user.pk, provider="google").exists(),
        "created_at": serializers.DateTimeField().to_representation(user.date_joined),
    }


# A primary-email change sends a verification email to the new address: the contract's purpose for both.
_DELIVERY_PURPOSES = {"email-verification": "email_verification", "primary-email-change": "email_verification"}
_DELIVERY_STATUSES = {
    EmailDelivery.Status.PENDING: "pending",
    EmailDelivery.Status.ACCEPTED: "provider_accepted",
    EmailDelivery.Status.FAILED: "failed",
    EmailDelivery.Status.UNKNOWN: "unknown",
    # Still "submitting" after the post-commit call returned: its outcome could not be persisted.
    EmailDelivery.Status.SUBMITTING: "unknown",
}


def delivery_summary(delivery: EmailDelivery) -> dict:
    """``EmailDeliverySummary``. ``provider_accepted`` is provider acceptance, never inbox delivery."""
    timestamp = serializers.DateTimeField()
    accepted = delivery.status == EmailDelivery.Status.ACCEPTED
    return {
        "id": str(delivery.pk),
        "purpose": _DELIVERY_PURPOSES[delivery.template],
        "status": _DELIVERY_STATUSES[EmailDelivery.Status(delivery.status)],
        "created_at": timestamp.to_representation(delivery.created_at),
        "last_attempt_at": timestamp.to_representation(delivery.last_attempt_at) if delivery.last_attempt_at else None,
        "provider_accepted_at": timestamp.to_representation(delivery.completed_at) if accepted and delivery.completed_at else None,
    }

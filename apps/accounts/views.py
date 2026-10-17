"""Authentication and email lifecycle operations (Documentation ``api/openapi.yaml``, Backend#8, Backend#35).

CSRF bootstrap, signup, login, logout and current user; initial email verification and its resend; the
primary-email change request and verification.

Security properties (ADR-011, ADR-013, ADR-015, ADR-016):

- Every unsafe operation, public ones included, is CSRF-checked by ``ContractViewMixin``.
- Signup and login are rate-limited by ``apps.ratelimit`` before any password work, with the counters
  recorded outside the domain transaction so a failed request still counts.
- Signup creates the user, its unverified allauth ``EmailAddress``, the verification bearer and the
  delivery record in one transaction; the email is submitted after the commit and its failure never
  undoes the account. The new session is restricted: the verification gate keeps household operations
  closed until the email is verified.
- Signup and login rotate the session key, keeping only a valid pending invitation intent; logout flushes
  the session, intent included.
- ``verifyEmail`` consumes an initial-verification bearer without treating it as a login credential: it
  only rotates the same browser's matching restricted session; any other browser stays as it was.
  ``resendEmailVerification`` issues a new bearer (superseding the old one) and a new delivery, so a failed
  delivery is recovered by a rate-limited resend.
- The primary-email change requires a verified account and a recent authentication in the current session
  (ADR-016: 5 minutes) for both the request and the verification, and the verification must happen in the
  session that requested the change. Completing it rotates that session and revokes all others.
- Every response of these operations is ``Cache-Control: private, no-store``.
"""

from allauth.account.models import EmailAddress
from django.contrib.auth import logout
from django.contrib.auth.backends import ModelBackend
from django.db import IntegrityError, transaction
from django.middleware.csrf import get_token
from psycopg import errors as pg_errors
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.errors import Conflict
from apps.api.views import ApiView
from apps.email_delivery.models import EmailDelivery
from apps.ratelimit import limiter

from .email_change import complete_primary_email_change, request_primary_email_change
from .models import User
from .serializers import (
    LoginSerializer,
    PrimaryEmailChangeSerializer,
    SignupSerializer,
    VerifierSerializer,
    delivery_summary,
    user_response,
)
from .sessions import PRIMARY_EMAIL_CHANGE_SESSION_KEY, establish_session, recently_authenticated, rotate_session
from .verification import EmailAlreadyVerified, issue_email_verification, verify_initial_email

PASSWORD_BACKEND = "django.contrib.auth.backends.ModelBackend"
NO_STORE = "private, no-store"


class EmailAlreadyRegistered(Conflict):
    default_detail = "An account with this email address already exists."


class AuthView(ApiView):
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = NO_STORE
        return response


class CsrfTokenView(AuthView):
    """``getCsrfToken``: sets (or refreshes) the readable CSRF cookie and returns its token."""

    permission_classes = [AllowAny]
    allow_unverified = True

    def get(self, request):
        return Response({"csrf_token": get_token(request)})


class SignupView(AuthView):
    """``signup``: 201 with a restricted session, 400, 409 for a registered address, 429."""

    permission_classes = [AllowAny]
    allow_unverified = True

    def post(self, request):
        limiter.consume("signup_ip", request=request)
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        limiter.consume("signup_email", email=data["email"])

        user = User(email=data["email"], name=data["name"])
        user.set_password(data["password"])  # hashed before the transaction opens
        try:
            with transaction.atomic():
                if EmailAddress.objects.filter(email__iexact=user.email).exists():
                    raise EmailAlreadyRegistered()
                user.save(force_insert=True)
                EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=False)
                issued = issue_email_verification(request, user)
        except IntegrityError as exc:
            # A concurrent signup for the same address lost the race on a unique index.
            if isinstance(exc.__cause__, pg_errors.UniqueViolation):
                raise EmailAlreadyRegistered() from exc
            raise
        # The post-commit submission has run (or been skipped) by now; report its honest outcome.
        delivery = EmailDelivery.objects.get(pk=issued.delivery.pk)

        establish_session(request, user, backend=PASSWORD_BACKEND)
        body = {"user": user_response(user), "email_verification_required": True, "delivery": delivery_summary(delivery)}
        return Response(body, status=status.HTTP_201_CREATED)


class LoginView(AuthView):
    """``login``: 200 (restricted session when unverified), 400, 401, 429."""

    permission_classes = [AllowAny]
    allow_unverified = True

    def post(self, request):
        limiter.consume("login_ip", request=request)
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email, password = serializer.validated_data["email"], serializer.validated_data["password"]
        # Reserve a failure slot before checking the password: concurrent guesses cannot exceed the
        # limit, and a refused login is refused even with the right password (no oracle). Counted for
        # every submitted address, registered or not.
        limiter.consume("login_failed_email", email=email)

        # ModelBackend runs the password hasher for unknown addresses too and refuses disabled accounts.
        user = ModelBackend().authenticate(request, username=email, password=password)
        if user is None:
            raise AuthenticationFailed()
        limiter.clear("login_failed_email", email=email)

        establish_session(request, user, backend=PASSWORD_BACKEND)
        body = {"user": user_response(user), "email_verification_required": not user.is_email_verified}
        return Response(body)


class LogoutView(AuthView):
    """``logout``: 204, flushing the session (pending invitation intent included); 401 without one."""

    allow_unverified = True

    def post(self, request):
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class CurrentUserView(AuthView):
    """``getCurrentUser``: 200 ``UserResponse``, also for a restricted pre-verification session; 401."""

    allow_unverified = True

    def get(self, request):
        return Response(user_response(request.user))


def require_recent_authentication(request) -> None:
    """403 unless the current session authenticated within the ADR-016 recent-reauthentication window."""
    if not recently_authenticated(request):
        raise PermissionDenied()


class VerifyEmailView(AuthView):
    """``verifyEmail``: 204; 400 for a malformed body or any unusable bearer; 409 when already verified; 429.

    Public, so a restricted session or no session at all may call it. The bearer verifies the account's
    email and never authenticates: only when this browser's session is the bearer account's restricted
    session is that session rotated (keeping its invitation intent); otherwise no session is created,
    changed or upgraded, and the user logs in normally.
    """

    permission_classes = [AllowAny]
    allow_unverified = True

    def post(self, request):
        limiter.consume("verify_email_ip", request=request)
        serializer = VerifierSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = verify_initial_email(serializer.validated_data["verifier"])
        if request.user.is_authenticated and request.user.pk == user.pk:
            rotate_session(request)  # the session's privileges just changed
        return Response(status=status.HTTP_204_NO_CONTENT)


class ResendEmailVerificationView(AuthView):
    """``resendEmailVerification``: 200 with the new delivery; 401; 409 when already verified; 429.

    The new bearer supersedes every earlier one. A delivery failure is reported, never rolled back: the
    account keeps a usable bearer and may resend again within the rate limits.
    """

    allow_unverified = True

    def post(self, request):
        user = request.user
        if user.is_email_verified:
            raise EmailAlreadyVerified()
        limiter.consume("resend_email_verification_user", user=user)
        with transaction.atomic():
            issued = issue_email_verification(request, user)  # takes the account lock first
            if user.is_email_verified:  # verified concurrently: re-read under the lock
                raise EmailAlreadyVerified()
        delivery = EmailDelivery.objects.get(pk=issued.delivery.pk)
        return Response({"delivery": delivery_summary(delivery)})


class RequestPrimaryEmailChangeView(AuthView):
    """``requestPrimaryEmailChange``: 202 with the delivery; 400; 401; 403 without recent authentication; 409; 429."""

    def post(self, request):
        require_recent_authentication(request)
        limiter.consume("email_change_user", user=request.user)
        serializer = PrimaryEmailChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_email = serializer.validated_data["new_email"]
        limiter.consume("email_change_email", email=new_email)
        with transaction.atomic():
            requested = request_primary_email_change(request, request.user, new_email)
        # Binds the pending change to this session; the identifier is not a credential.
        request.session[PRIMARY_EMAIL_CHANGE_SESSION_KEY] = str(requested.change.pk)
        delivery = EmailDelivery.objects.get(pk=requested.delivery.pk)
        return Response({"delivery": delivery_summary(delivery)}, status=status.HTTP_202_ACCEPTED)


class VerifyPrimaryEmailChangeView(AuthView):
    """``verifyPrimaryEmailChange``: 204 with a rotated session; 400; 401; 403 without recent authentication; 409; 429."""

    def post(self, request):
        require_recent_authentication(request)
        limiter.consume("verify_email_change_user", user=request.user)
        serializer = VerifierSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        complete_primary_email_change(request, request.user, serializer.validated_data["verifier"])
        return Response(status=status.HTTP_204_NO_CONTENT)

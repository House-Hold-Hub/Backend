"""CSRF bootstrap, signup, login, logout and current user (Documentation ``api/openapi.yaml``, Backend#8).

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
- Every response of these operations is ``Cache-Control: private, no-store``.
"""

from allauth.account.models import EmailAddress
from django.contrib.auth import logout
from django.contrib.auth.backends import ModelBackend
from django.db import IntegrityError, transaction
from django.middleware.csrf import get_token
from psycopg import errors as pg_errors
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.errors import Conflict
from apps.api.views import ApiView
from apps.email_delivery.models import EmailDelivery
from apps.ratelimit import limiter

from .models import User
from .serializers import LoginSerializer, SignupSerializer, delivery_summary, user_response
from .sessions import establish_session
from .verification import issue_email_verification

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

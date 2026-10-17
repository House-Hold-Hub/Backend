"""Routes served under ``/api/v1/``.

Each feature app contributes its operations here as it implements them, following the
Documentation-owned OpenAPI contract. ``manage.py check_api_contract`` fails if a route
here (or any API view mounted elsewhere) diverges from that contract.
"""

from django.urls import URLPattern, URLResolver, path

from apps.accounts import views as accounts

urlpatterns: list[URLPattern | URLResolver] = [
    path("auth/csrf", accounts.CsrfTokenView.as_view(), name="auth-csrf"),
    path("auth/signup", accounts.SignupView.as_view(), name="auth-signup"),
    path("auth/login", accounts.LoginView.as_view(), name="auth-login"),
    path("auth/logout", accounts.LogoutView.as_view(), name="auth-logout"),
    path("auth/me", accounts.CurrentUserView.as_view(), name="auth-me"),
    path("auth/email/verify", accounts.VerifyEmailView.as_view(), name="auth-email-verify"),
    path("auth/email/resend-verification", accounts.ResendEmailVerificationView.as_view(), name="auth-email-resend"),
    path("auth/email/change", accounts.RequestPrimaryEmailChangeView.as_view(), name="auth-email-change"),
    path("auth/email/change/verify", accounts.VerifyPrimaryEmailChangeView.as_view(), name="auth-email-change-verify"),
]

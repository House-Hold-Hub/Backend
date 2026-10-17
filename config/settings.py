"""Django settings for HouseHoldHub Backend, configured through the environment."""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None, *, required=False):
    value = os.environ.get(name, default)
    if required and value in (None, ""):
        raise ImproperlyConfigured(f"Missing required environment variable: {name}")
    return value


def env_bool(name, default=False):
    return str(os.environ.get(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


SECRET_KEY = env("DJANGO_SECRET_KEY", required=True)
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS")
# Same-origin is the default topology: no CORS configuration. Trusted origins
# are only needed behind a TLS-terminating proxy that rewrites the origin.
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "apps.accounts",
    "apps.api",
    "apps.email_delivery",
    "apps.ratelimit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", "householdhub"),
        "USER": env("POSTGRES_USER", "householdhub"),
        "PASSWORD": env("POSTGRES_PASSWORD", ""),
        "HOST": env("POSTGRES_HOST", "localhost"),
        "PORT": env("POSTGRES_PORT", "5432"),
    }
}

# Custom UUID user; must be set before the first migration is generated.
AUTH_USER_MODEL = "accounts.User"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# django-allauth (ADR-010, ADR-011): the normalized email is the only login identity, the user
# model has no username, and email ownership must be verified. Verified-email state lives in
# allauth's EmailAddress (User.is_email_verified). allauth's own rate limiter is off: ADR-016 replaces it
# with apps.ratelimit (atomic PostgreSQL counters, HMAC keys, 429 instead of a form error).
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*"]
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_RATE_LIMITS = False
# ADR-016 recent reauthentication: an authentication recorded in the current session within 5 minutes.
# apps.accounts.sessions.recently_authenticated reads it (allauth's own check waives it for social-only
# accounts, ours never does).
ACCOUNT_REAUTHENTICATION_TIMEOUT = 5 * 60

# ADR-016 password policy: 15 to 128 Unicode code points, common-password and similarity checks, no
# composition rules (so no NumericPasswordValidator). Django's default hasher and work factor.

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
        "OPTIONS": {"user_attributes": ("email", "name")},
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 15}},
    {"NAME": "apps.accounts.validators.MaximumLengthValidator", "OPTIONS": {"max_length": 128}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]

# ADR-016 authentication rate limits as {action: ((per, limit, window_seconds), ...)}, per "ip", "email"
# or "user"; enforced by apps.ratelimit. Each action has one subject so a view consumes it when that
# subject is known (the email only after the body validated). Login counts failures per address:
# a slot is reserved before the password check and released by a successful login.
AUTH_RATE_LIMITS = {
    "signup_ip": (("ip", 10, 60 * 60),),
    "signup_email": (("email", 3, 60 * 60),),
    "login_ip": (("ip", 30, 60),),
    "login_failed_email": (("email", 5, 5 * 60),),
    "verify_email_ip": (("ip", 20, 5 * 60),),
    "resend_email_verification_user": (("user", 1, 2 * 60), ("user", 5, 60 * 60)),
    "email_change_user": (("user", 5, 60 * 60),),
    "email_change_email": (("email", 3, 60 * 60),),
    "verify_email_change_user": (("user", 10, 5 * 60),),
}
# Proxies Infrastructure puts in front of the service (0: use the peer address, ignore X-Forwarded-For).
RATE_LIMIT_TRUSTED_PROXY_COUNT = 0
RATE_LIMIT_IPV6_PREFIX = 64

# ADR-016 one-time bearer lifetimes: initial email verification (signup, resend) and primary-email change.
AUTH_EMAIL_VERIFICATION_LIFETIME_SECONDS = 24 * 60 * 60
AUTH_PRIMARY_EMAIL_CHANGE_LIFETIME_SECONDS = 60 * 60
# Frontend routes that read those bearers from the URI fragment (same origin as the API).
FRONTEND_EMAIL_VERIFICATION_PATH = "/verify-email"
FRONTEND_PRIMARY_EMAIL_CHANGE_PATH = "/verify-email-change"

# ADR-011: database-backed sessions, 14-day expiry, HttpOnly session cookie,
# readable CSRF cookie (sent back as X-CSRFToken), SameSite=Lax for OAuth redirects.
# The engine is Django's database store on accounts.Session, whose indexed user column is the
# user-session registry used for revocation (apps/accounts/sessions.py). django.contrib.sessions
# stays installed for its middleware and the scheduled `clearsessions` cleanup command.
SESSION_ENGINE = "apps.accounts.sessions"
SESSION_COOKIE_AGE = 14 * 24 * 60 * 60
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = env_bool("DJANGO_SECURE_COOKIES", not DEBUG)
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE

# ADR-015: transactional email goes through a provider-neutral adapter, called synchronously after the
# domain commit with a bounded timeout. The managed provider is deferred (D02), so the default records an
# honest "not configured" failure instead of sending. No environment variables: nothing for Infrastructure
# to mirror until D02 selects a provider.
EMAIL_DELIVERY = {
    "PROVIDER": "apps.email_delivery.adapter.UnconfiguredProvider",
    "TIMEOUT_SECONDS": 5.0,
    # A pending/submitting record older than this was left by an interrupted process (reconciler).
    "STALE_AFTER_SECONDS": 300,
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ADR-002 / ADR-014: JSON-only DRF API under /api/v1 with Django cookie-session authentication.
# Fail-closed defaults: every view requires authentication unless it explicitly opts out
# (public operations declare `security: []` in the Documentation OpenAPI contract).
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.api.authentication.ApiSessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "apps.api.pagination.PageLimitPagination",
    "EXCEPTION_HANDLER": "apps.api.errors.exception_handler",
}

from pathlib import Path

from django.conf import settings
from django.urls import get_resolver
from rest_framework.settings import api_settings

from apps.api import pagination
from apps.api.authentication import ApiSessionAuthentication
from apps.api.errors import ErrorCode, exception_handler


def test_drf_is_installed_and_json_only():
    assert "rest_framework" in settings.INSTALLED_APPS
    assert "apps.api" in settings.INSTALLED_APPS
    assert [r.__name__ for r in api_settings.DEFAULT_RENDERER_CLASSES] == ["JSONRenderer"]
    assert [p.__name__ for p in api_settings.DEFAULT_PARSER_CLASSES] == ["JSONParser"]


def test_session_cookie_authentication_is_the_only_authentication():
    assert list(api_settings.DEFAULT_AUTHENTICATION_CLASSES) == [ApiSessionAuthentication]


def test_views_require_authentication_unless_they_opt_out():
    assert [p.__name__ for p in api_settings.DEFAULT_PERMISSION_CLASSES] == ["IsAuthenticated"]


def test_pagination_and_error_handler_are_wired():
    assert api_settings.DEFAULT_PAGINATION_CLASS is pagination.PageLimitPagination
    assert api_settings.EXCEPTION_HANDLER is exception_handler


def test_session_and_csrf_cookie_settings_follow_adr_011():
    assert settings.SESSION_COOKIE_NAME == "sessionid"
    assert settings.SESSION_COOKIE_HTTPONLY is True
    assert settings.CSRF_COOKIE_HTTPONLY is False  # readable so the frontend can send X-CSRFToken
    assert settings.CSRF_HEADER_NAME == "HTTP_X_CSRFTOKEN"
    assert "django.middleware.csrf.CsrfViewMiddleware" in settings.MIDDLEWARE


def test_api_is_mounted_under_the_versioned_prefix():
    assert any(str(p.pattern) == "api/v1/" for p in get_resolver().url_patterns)


def test_no_endpoint_is_published_before_its_feature_issue():
    from apps.api.urls import urlpatterns

    assert urlpatterns == []


def test_error_codes_never_include_unused_http_statuses():
    assert "422" not in {str(code) for code in ErrorCode}


def test_no_backend_generated_schema_is_published():
    names = {r.pattern.regex.pattern for r in get_resolver().url_patterns}
    assert not any("schema" in n or "openapi" in n for n in names)
    assert "drf_spectacular" not in settings.INSTALLED_APPS
    root = Path(settings.BASE_DIR)
    stray = [
        p
        for pattern in ("openapi*.y*ml", "openapi*.json", "swagger*.y*ml", "swagger*.json")
        for p in root.rglob(pattern)
        if ".venv" not in p.parts and ".git" not in p.parts
    ]
    assert stray == [], f"Backend must not carry an OpenAPI artifact: {stray}"

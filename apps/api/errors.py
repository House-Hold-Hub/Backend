"""Error semantics of the API (ADR-014, ``ErrorResponse`` in the Documentation OpenAPI).

Every API error body is ``{"code", "message"[, "fields"]}``. Messages for 401/403/404
are fixed so that they never disclose whether an out-of-scope resource exists.
"""

from enum import StrEnum

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.http import Http404
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import set_rollback


class ErrorCode(StrEnum):
    """Wire values of ``ErrorResponse.code``; the contract check compares this set to the contract enum."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


def error_body(code, message, fields=None):
    body = {"code": str(code), "message": message}
    if fields:
        body["fields"] = fields
    return body


def flatten_validation_detail(detail, prefix=""):
    """Flatten DRF validation detail into ``{field: [message, ...]}`` (dotted paths for nesting)."""
    fields = {}

    def add(key, messages):
        fields.setdefault(key or "non_field_errors", []).extend(messages)

    if isinstance(detail, dict):
        for key, value in detail.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            for sub_key, messages in flatten_validation_detail(value, path).items():
                fields.setdefault(sub_key, []).extend(messages)
    elif isinstance(detail, (list, tuple)):
        plain = [str(item) for item in detail if not isinstance(item, (dict, list, tuple))]
        if plain:
            add(prefix, plain)
        for index, item in enumerate(detail):
            if isinstance(item, (dict, list, tuple)):
                path = f"{prefix}.{index}" if prefix else str(index)
                for sub_key, messages in flatten_validation_detail(item, path).items():
                    fields.setdefault(sub_key, []).extend(messages)
    else:
        add(prefix, [str(detail)])
    return fields


def exception_handler(exc, context):
    """DRF exception handler producing ``ErrorResponse`` bodies.

    401 is returned for every authentication failure (DRF would otherwise coerce it to 403
    for cookie-session authentication). Anything that is not an API/404/403 exception is
    left unhandled so it reaches Django's 500 handling.
    """
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, DjangoPermissionDenied):
        exc = exceptions.PermissionDenied()
    if not isinstance(exc, exceptions.APIException):
        return None

    headers = {}
    if isinstance(exc, (exceptions.NotAuthenticated, exceptions.AuthenticationFailed)):
        http_status = status.HTTP_401_UNAUTHORIZED
        body = error_body(ErrorCode.AUTHENTICATION_ERROR, "Authentication is required.")
    elif isinstance(exc, exceptions.PermissionDenied):
        http_status = status.HTTP_403_FORBIDDEN
        body = error_body(ErrorCode.AUTHORIZATION_ERROR, "You do not have permission to perform this action.")
    elif isinstance(exc, exceptions.NotFound):
        http_status = status.HTTP_404_NOT_FOUND
        body = error_body(ErrorCode.NOT_FOUND, "Not found.")
    elif isinstance(exc, exceptions.Throttled):
        http_status = status.HTTP_429_TOO_MANY_REQUESTS
        body = error_body(ErrorCode.RATE_LIMITED, "Too many requests.")
        if exc.wait is not None:
            headers["Retry-After"] = str(int(exc.wait))
    elif isinstance(exc, exceptions.ValidationError):
        http_status = status.HTTP_400_BAD_REQUEST
        body = error_body(ErrorCode.VALIDATION_ERROR, "Validation failed.", flatten_validation_detail(exc.detail))
    elif isinstance(exc, exceptions.ParseError):
        http_status = status.HTTP_400_BAD_REQUEST
        body = error_body(ErrorCode.VALIDATION_ERROR, "Malformed request.")
    else:
        # Statuses the contract does not enumerate (405, 406, 415, ...) keep their HTTP status.
        http_status = exc.status_code
        code = ErrorCode.INTERNAL_ERROR if http_status >= 500 else ErrorCode.VALIDATION_ERROR
        body = error_body(code, str(exc.detail))

    set_rollback()
    return Response(body, status=http_status, headers=headers)

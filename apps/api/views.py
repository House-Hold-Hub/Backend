"""Base view for every ``/api/v1`` endpoint."""

from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView

from .authentication import ApiSessionAuthentication


def has_application_access(user):
    """Whether ``user`` may use protected application operations.

    Requires an authenticated, enabled account whose email django-allauth records as verified
    (ADR-011, security model). Anything that cannot be established is a denial.
    """
    return bool(
        user is not None
        and user.is_authenticated
        and getattr(user, "is_active", False)
        and getattr(user, "is_email_verified", False)
    )


class ContractViewMixin:
    """Mandatory base of every ``/api/v1`` view (the contract check rejects views without it).

    Public does not mean CSRF-exempt: after authentication and permission checks (so an
    unauthenticated call to a protected operation is still a 401), CSRF is enforced for all
    unsafe methods, including anonymous ones such as login or signup.

    It is also the single verification gate. An authenticated account without a verified email
    is answered 403 before the view's own permission classes run (so a household-scoped class
    cannot turn it into a 404 or skip the gate), unless the view sets ``allow_unverified``.
    ``allow_unverified`` is opt-in per view and is only for public operations and the
    verification lifecycle the contract allows before verification (``contract.py`` rejects
    any other operation that sets it). Anonymous callers are untouched here: authentication is
    the permission classes' concern and yields 401.
    """

    allow_unverified = False

    def check_permissions(self, request):
        if not self.allow_unverified:
            user = request.user
            if user is not None and user.is_authenticated and not has_application_access(user):
                raise PermissionDenied()
        super().check_permissions(request)  # type: ignore[misc]

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)  # type: ignore[misc]
        ApiSessionAuthentication().enforce_csrf(request._request)


class ApiView(ContractViewMixin, APIView):
    pass

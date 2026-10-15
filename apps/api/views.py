"""Base view for every ``/api/v1`` endpoint."""

from rest_framework.views import APIView

from .authentication import ApiSessionAuthentication


class ContractViewMixin:
    """Mandatory base of every ``/api/v1`` view (the contract check rejects views without it).

    Public does not mean CSRF-exempt: after authentication and permission checks (so an
    unauthenticated call to a protected operation is still a 401), CSRF is enforced for all
    unsafe methods, including anonymous ones such as login or signup.
    """

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)  # type: ignore[misc]
        ApiSessionAuthentication().enforce_csrf(request._request)


class ApiView(ContractViewMixin, APIView):
    pass

from rest_framework.authentication import SessionAuthentication


class ApiSessionAuthentication(SessionAuthentication):
    """Django cookie-session authentication (ADR-004/ADR-011).

    Inherits CSRF validation for authenticated requests. CSRF for requests without a
    session (public unsafe operations) is enforced by ``ContractViewMixin``.
    """

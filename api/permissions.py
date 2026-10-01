from __future__ import annotations

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

_ACTIVE_MEMBERSHIP_ATTRIBUTE = "_householdhub_active_membership"
_NOT_RESOLVED = object()


class HouseholdScopedPermission(BasePermission):
    """Fail-closed base permission for household-owned API resources."""

    def _active_membership(self, request: Request, view: APIView) -> object | None:
        cached: object = getattr(request, _ACTIVE_MEMBERSHIP_ATTRIBUTE, _NOT_RESOLVED)
        if cached is not _NOT_RESOLVED:
            return cached

        user = getattr(request, "user", None)
        membership: object | None
        if user is None or not bool(getattr(user, "is_authenticated", False)):
            membership = None
        else:
            resolver = getattr(view, "get_active_household_membership", None)
            membership = resolver(request) if callable(resolver) else None

        setattr(request, _ACTIVE_MEMBERSHIP_ATTRIBUTE, membership)
        return membership

    def has_permission(self, request: Request, view: APIView) -> bool:
        return self._active_membership(request, view) is not None

    def has_object_permission(self, request: Request, view: APIView, obj: object) -> bool:
        membership = self._active_membership(request, view)
        if membership is None:
            return False
        return self.has_household_object_permission(request, view, obj, membership)

    def has_household_object_permission(
        self,
        request: Request,
        view: APIView,
        obj: object,
        membership: object,
    ) -> bool:
        """Override for action/object rules after household membership is established."""
        return False

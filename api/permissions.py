from __future__ import annotations

from typing import Any

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

_ACTIVE_MEMBERSHIP_ATTR = "_householdhub_active_membership"


class ActiveHouseholdMembershipPermission(BasePermission):
    """Require a view to resolve an active membership before household access."""

    message = "Active household membership is required."

    def has_permission(self, request: Request, view: APIView) -> bool:
        if not request.user.is_authenticated:
            return False

        resolver = getattr(view, "get_active_household_membership", None)
        if not callable(resolver):
            return False

        membership = resolver()
        if membership is None:
            return False

        setattr(view, _ACTIVE_MEMBERSHIP_ATTR, membership)
        return True

    @staticmethod
    def get_active_membership(view: APIView) -> Any | None:
        return getattr(view, _ACTIVE_MEMBERSHIP_ATTR, None)


class HouseholdObjectPermission(ActiveHouseholdMembershipPermission):
    """Scope an object to the active membership before action authorization."""

    def get_object_household_id(self, obj: Any) -> Any | None:
        return getattr(obj, "household_id", None)

    def has_household_object_permission(
        self,
        request: Request,
        view: APIView,
        obj: Any,
    ) -> bool:
        return True

    def has_object_permission(self, request: Request, view: APIView, obj: Any) -> bool:
        membership = self.get_active_membership(view)
        if membership is None:
            return False

        membership_household_id = getattr(membership, "household_id", None)
        object_household_id = self.get_object_household_id(obj)
        if (
            membership_household_id is None
            or object_household_id is None
            or membership_household_id != object_household_id
        ):
            return False

        return self.has_household_object_permission(request, view, obj)

"""Household-scoped permission base classes (ADR-005, ADR-012, security model).

Evaluation order, fail-closed at every step:

1. Unauthenticated callers get 401 before anything household-related is touched.
2. The caller must hold an *active* membership of the household in the URL; otherwise 404,
   identical for a nonexistent household and one the caller does not belong to. Action and
   object permissions are never evaluated for a non-member.
3. The action permission of the permissions matrix is applied; a denial is 403.
4. For object endpoints the membership is obtained again through the same path: it is
   resolved once per request and cached on the request for that household, and resolved
   afresh if the cache has no entry (e.g. ``has_permission`` was bypassed). The object must
   then belong to the URL household (otherwise 404), and only then is the object permission
   applied (403). The cache never outlives the request, so removal takes effect on the next one.

Everything defaults to deny: a subclass has to grant explicitly, and
``resolve_membership`` has no default so an unwired class can never grant access.
"""

from django.core.exceptions import ImproperlyConfigured
from rest_framework.exceptions import NotAuthenticated, NotFound
from rest_framework.permissions import BasePermission


class HouseholdScopedPermission(BasePermission):
    household_url_kwarg = "household_id"

    def resolve_membership(self, user, household_id):
        """Return the user's *active* membership of the household, or ``None``.

        "Active" covers every current-state condition (membership not removed, household
        not soft-deleted, user enabled). Implemented by the Membership app (Backend#12).
        """
        raise NotImplementedError(f"{type(self).__name__}.resolve_membership() must be implemented.")

    def has_action_permission(self, request, view, membership):
        """Collection/action level rule from the permissions matrix. Default: deny."""
        return False

    def has_object_action_permission(self, request, view, obj, membership):
        """Object level rule from the permissions matrix. Default: deny."""
        return False

    def get_object_household_id(self, obj):
        return getattr(obj, "household_id", None)

    def has_permission(self, request, view):
        membership = self._require_membership(request, view)
        return bool(self.has_action_permission(request, view, membership))

    def has_object_permission(self, request, view, obj):
        membership = self._require_membership(request, view)
        household_id = self._household_id(view)
        object_household_id = self.get_object_household_id(obj)
        if object_household_id is None or str(object_household_id) != str(household_id):
            raise NotFound()
        return bool(self.has_object_action_permission(request, view, obj, membership))

    def _household_id(self, view):
        try:
            return view.kwargs[self.household_url_kwarg]
        except KeyError:
            raise ImproperlyConfigured(
                f"{type(view).__name__} uses {type(self).__name__} but its route has no "
                f"'{self.household_url_kwarg}' URL kwarg."
            ) from None

    def _require_membership(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            raise NotAuthenticated()
        household_id = self._household_id(view)
        cached = getattr(request, "household_membership", None)
        if cached is not None and cached[0] == str(household_id):
            return cached[1]
        membership = self.resolve_membership(user, household_id)
        if membership is None:
            raise NotFound()
        request.household_membership = (str(household_id), membership)
        return membership


class IsActiveHouseholdMember(HouseholdScopedPermission):
    """Any active member may act on the household and its objects (e.g. view/create)."""

    def has_action_permission(self, request, view, membership):
        return True

    def has_object_action_permission(self, request, view, obj, membership):
        return True

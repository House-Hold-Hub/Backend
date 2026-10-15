"""Test-only views and URLconf. Production code ships no endpoints until the feature issues land."""

import uuid
from dataclasses import dataclass

from django.http import Http404, JsonResponse
from django.middleware.csrf import get_token
from django.urls import path
from rest_framework import exceptions
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.api.pagination import PageLimitPagination
from apps.api.permissions import HouseholdScopedPermission
from apps.api.views import ApiView

# --- in-memory membership fixtures (no Household/Membership models exist yet: Backend#11/#12) ---

MEMBERSHIPS = {}  # (user_pk, household_id as str) -> role
OBJECTS = {}  # object id (str) -> Obj
CALLS = []  # ordered record of permission hooks that ran


@dataclass
class Obj:
    household_id: uuid.UUID
    creator_id: object


class RecordingPermission(HouseholdScopedPermission):
    def resolve_membership(self, user, household_id):
        CALLS.append("resolve_membership")
        return MEMBERSHIPS.get((user.pk, str(household_id)))

    def has_action_permission(self, request, view, membership):
        CALLS.append("action")
        return request.method in ("GET", "POST")

    def has_object_action_permission(self, request, view, obj, membership):
        CALLS.append("object")
        return request.method == "GET" or obj.creator_id == request.user.pk


class DenyByDefaultPermission(HouseholdScopedPermission):
    def resolve_membership(self, user, household_id):
        return MEMBERSHIPS.get((user.pk, str(household_id)))


class UnwiredPermission(HouseholdScopedPermission):
    pass


class PublicPost(ApiView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"ok": True})

    def post(self, request):
        return Response({"ok": True})


class ProtectedPost(ApiView):
    def get(self, request):
        return Response({"ok": True})

    def post(self, request):
        return Response({"ok": True})


class Conflict(exceptions.APIException):
    status_code = 409


class Boom(ApiView):
    permission_classes = [AllowAny]

    def get(self, request):
        kind = request.query_params["kind"]
        if kind == "validation":
            raise exceptions.ValidationError({"name": ["required"], "items": [{"qty": ["bad"]}], "x": "plain"})
        if kind == "non_field":
            raise exceptions.ValidationError(["generic"])
        if kind == "throttled":
            raise exceptions.Throttled(wait=7)
        if kind == "parse":
            raise exceptions.ParseError()
        if kind == "http404":
            raise Http404
        if kind == "conflict":
            raise Conflict("Duplicate membership.")
        if kind == "method":
            raise exceptions.MethodNotAllowed("get")
        raise RuntimeError("unexpected")


class Numbers(ApiView):
    pagination_class = PageLimitPagination
    permission_classes = [AllowAny]

    def get(self, request):
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(list(range(250)), request, self)
        return paginator.get_paginated_response(page)


class HouseholdItems(ApiView):
    permission_classes = [RecordingPermission]

    def get(self, request, household_id):
        return Response({"household": str(household_id)})

    def post(self, request, household_id):
        return Response({"created": True})

    def delete(self, request, household_id):
        return Response(status=204)


class HouseholdItem(ApiView):
    permission_classes = [RecordingPermission]

    def _get_object(self, request, item_id):
        try:
            obj = OBJECTS[str(item_id)]
        except KeyError:
            raise Http404 from None
        self.check_object_permissions(request, obj)
        return obj

    def get(self, request, household_id, item_id):
        self._get_object(request, item_id)
        return Response({"ok": True})

    def post(self, request, household_id, item_id):
        self._get_object(request, item_id)
        return Response({"ok": True})


class DefaultDeny(ApiView):
    permission_classes = [DenyByDefaultPermission]

    def get(self, request, household_id):
        return Response({"ok": True})


class Unwired(ApiView):
    permission_classes = [UnwiredPermission]

    def get(self, request, household_id):
        return Response({"ok": True})


class NoHouseholdKwarg(ApiView):
    permission_classes = [RecordingPermission]

    def get(self, request):
        return Response({"ok": True})


def csrf_bootstrap(request):
    return JsonResponse({"csrf_token": get_token(request)})


handler404 = "apps.api.handlers.not_found"
handler500 = "apps.api.handlers.server_error"

urlpatterns = [
    path("api/v1/csrf", csrf_bootstrap),
    path("api/v1/public", PublicPost.as_view()),
    path("api/v1/protected", ProtectedPost.as_view()),
    path("api/v1/boom", Boom.as_view()),
    path("api/v1/numbers", Numbers.as_view()),
    path("api/v1/households/<uuid:household_id>/items", HouseholdItems.as_view()),
    path("api/v1/households/<uuid:household_id>/items/<uuid:item_id>", HouseholdItem.as_view()),
    path("api/v1/households/<uuid:household_id>/default-deny", DefaultDeny.as_view()),
    path("api/v1/households/<uuid:household_id>/unwired", Unwired.as_view()),
    path("api/v1/no-household", NoHouseholdKwarg.as_view()),
]

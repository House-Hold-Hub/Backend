from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from django.conf import settings
from django.urls import URLResolver, get_resolver
from rest_framework.request import Request
from rest_framework.views import APIView

from api.pagination import HouseholdHubPageNumberPagination
from api.permissions import ActiveHouseholdMembershipPermission, HouseholdObjectPermission


class MembershipView(APIView):
    def __init__(self, membership: object | None) -> None:
        super().__init__()
        self._membership = membership

    def get_active_household_membership(self) -> object | None:
        return self._membership


class AllowMarkedObjectPermission(HouseholdObjectPermission):
    def __init__(self) -> None:
        self.object_check_called = False

    def has_household_object_permission(
        self,
        request: Request,
        view: APIView,
        obj: Any,
    ) -> bool:
        self.object_check_called = True
        return bool(getattr(obj, "allowed", False))


def authenticated_request() -> Request:
    return cast(
        Request,
        SimpleNamespace(user=SimpleNamespace(is_authenticated=True)),
    )


def test_drf_base_configuration_matches_contract_defaults() -> None:
    assert "rest_framework" in settings.INSTALLED_APPS
    assert settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] == [
        "rest_framework.authentication.SessionAuthentication"
    ]
    assert settings.REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] == [
        "rest_framework.permissions.IsAuthenticated"
    ]
    assert settings.REST_FRAMEWORK["DEFAULT_PAGINATION_CLASS"] == (
        "api.pagination.HouseholdHubPageNumberPagination"
    )
    assert settings.REST_FRAMEWORK["PAGE_SIZE"] == 20

    pagination = HouseholdHubPageNumberPagination()
    assert pagination.page_size == 20
    assert pagination.page_size_query_param == "limit"
    assert pagination.max_page_size == 100


def test_api_v1_mount_exists_without_feature_routes() -> None:
    resolvers = [
        pattern
        for pattern in get_resolver().url_patterns
        if isinstance(pattern, URLResolver) and str(pattern.pattern) == "api/v1/"
    ]

    assert len(resolvers) == 1
    assert list(resolvers[0].url_patterns) == []


def test_active_membership_permission_fails_closed() -> None:
    permission = ActiveHouseholdMembershipPermission()
    request = authenticated_request()

    assert not permission.has_permission(request, MembershipView(None))
    assert not permission.has_permission(
        cast(Request, SimpleNamespace(user=SimpleNamespace(is_authenticated=False))),
        MembershipView(SimpleNamespace(household_id="household-a")),
    )


def test_object_authorization_runs_only_after_household_scope() -> None:
    request = authenticated_request()
    membership = SimpleNamespace(household_id="household-a")
    view = MembershipView(membership)

    permission = AllowMarkedObjectPermission()
    assert not permission.has_object_permission(
        request,
        view,
        SimpleNamespace(household_id="household-a", allowed=True),
    )
    assert not permission.object_check_called

    permission = AllowMarkedObjectPermission()
    assert permission.has_permission(request, view)
    assert not permission.has_object_permission(
        request,
        view,
        SimpleNamespace(household_id="household-b", allowed=True),
    )
    assert not permission.object_check_called

    permission = AllowMarkedObjectPermission()
    assert permission.has_permission(request, view)
    assert permission.has_object_permission(
        request,
        view,
        SimpleNamespace(household_id="household-a", allowed=True),
    )
    assert permission.object_check_called

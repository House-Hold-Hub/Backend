from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from django.conf import settings
from django.urls.resolvers import URLResolver, get_resolver

from api.pagination import ApiPagination
from api.permissions import HouseholdScopedPermission


class _MembershipView:
    def __init__(self, membership: object | None, events: list[str] | None = None) -> None:
        self.membership = membership
        self.events = events if events is not None else []
        self.calls = 0

    def get_active_household_membership(self, request: Any) -> object | None:
        self.calls += 1
        self.events.append("membership")
        return self.membership


class _AllowObjectPermission(HouseholdScopedPermission):
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def has_household_object_permission(
        self,
        request: Any,
        view: Any,
        obj: object,
        membership: object,
    ) -> bool:
        self.events.append("object")
        return True


def _request(*, authenticated: bool) -> Any:
    return cast(
        Any,
        SimpleNamespace(user=SimpleNamespace(is_authenticated=authenticated)),
    )


def test_drf_base_configuration_and_pagination_contract() -> None:
    assert "rest_framework" in settings.INSTALLED_APPS
    assert settings.REST_FRAMEWORK["DEFAULT_PAGINATION_CLASS"] == "api.pagination.ApiPagination"
    assert settings.REST_FRAMEWORK["PAGE_SIZE"] == 20

    pagination = ApiPagination()
    assert pagination.page_query_param == "page"
    assert pagination.page_size == 20
    assert pagination.page_size_query_param == "limit"
    assert pagination.max_page_size == 100


def test_api_is_mounted_once_under_versioned_prefix() -> None:
    api_resolvers = [
        entry
        for entry in get_resolver().url_patterns
        if isinstance(entry, URLResolver) and entry.urlconf_name == "api.urls"
    ]
    assert len(api_resolvers) == 1
    assert str(api_resolvers[0].pattern) == "api/v1/"


def test_household_permission_denies_unauthenticated_before_membership_lookup() -> None:
    view = _MembershipView(object())
    permission = HouseholdScopedPermission()

    assert not permission.has_permission(_request(authenticated=False), cast(Any, view))
    assert view.calls == 0


def test_household_permission_fails_closed_without_membership_resolver() -> None:
    permission = HouseholdScopedPermission()
    view = cast(Any, SimpleNamespace())

    assert not permission.has_permission(_request(authenticated=True), view)


def test_household_permission_base_object_rule_denies_by_default() -> None:
    permission = HouseholdScopedPermission()
    view = _MembershipView(object())

    assert not permission.has_object_permission(
        _request(authenticated=True),
        cast(Any, view),
        object(),
    )


def test_household_membership_is_checked_before_object_authorization() -> None:
    events: list[str] = []
    membership = object()
    view = _MembershipView(membership, events)
    permission = _AllowObjectPermission(events)

    assert permission.has_object_permission(
        _request(authenticated=True),
        cast(Any, view),
        object(),
    )
    assert events == ["membership", "object"]


def test_household_object_authorization_is_not_called_without_membership() -> None:
    events: list[str] = []
    view = _MembershipView(None, events)
    permission = _AllowObjectPermission(events)

    assert not permission.has_object_permission(
        _request(authenticated=True),
        cast(Any, view),
        object(),
    )
    assert events == ["membership"]

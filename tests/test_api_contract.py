from __future__ import annotations

from pathlib import Path

import pytest
from django.urls import include, path, re_path
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter, SimpleRouter
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from api import contract as contract_module
from api.contract import (
    ContractValidationError,
    Operation,
    check_current_implementation,
    collect_implemented_operations,
    load_contract_lock,
    parse_openapi_operations,
    validate_implemented_operations,
)


class GetWidgetView(APIView):
    def get(self, request: Request, item_id: object) -> Response:
        return Response({"id": str(item_id)})


class PostUnknownView(APIView):
    def post(self, request: Request) -> Response:
        return Response(status=204)


class WidgetViewSet(ViewSet):
    def retrieve(self, request: Request, pk: object | None = None) -> Response:
        return Response({"id": str(pk)})


class GetOnlyWidgetViewSet(ViewSet):
    http_method_names = ["get"]

    def list(self, request: Request) -> Response:
        return Response([])

    def create(self, request: Request) -> Response:
        return Response(status=201)


class NestedRegexWidgetViewSet(WidgetViewSet):
    lookup_value_regex = r"(?:foo\)|bar)"


class TraceWidgetViewSet(ViewSet):
    def list(self, request: Request) -> Response:
        return Response([])

    def trace(self, request: Request) -> Response:
        return Response(status=204)


class RouteMethodOverrideView(APIView):
    def get(self, request: Request) -> Response:
        return Response([])

    def post(self, request: Request) -> Response:
        return Response(status=201)


class HeadView(APIView):
    def head(self, request: Request) -> Response:
        return Response(status=204)


class OptionsView(APIView):
    def options(self, request: Request, *args: object, **kwargs: object) -> Response:
        return Response(status=204)


class TraceView(APIView):
    def trace(self, request: Request) -> Response:
        return Response(status=204)


def test_contract_lock_pins_documentation_openapi() -> None:
    lock = load_contract_lock()

    assert lock.repository == "House-Hold-Hub/Documentation"
    assert lock.path == "api/openapi.yaml"
    assert len(lock.revision) == 40
    assert len(lock.git_blob_sha) == 40
    assert Path(lock.path).name == "openapi.yaml"


def test_openapi_operation_parser_requires_operation_ids() -> None:
    contract = """openapi: 3.0.3
servers:
  - url: /api/v1
paths:
  /widgets/{item_id}:
    get:
      tags: [Widgets]
      operationId: getWidget
      responses: {}
"""
    operations = parse_openapi_operations(contract)

    assert operations == {Operation("GET", "/widgets/{item_id}"): "getWidget"}

    missing_operation_id = """openapi: 3.0.3
paths:
  /widgets:
    get:
      responses: {}
"""
    with pytest.raises(ContractValidationError, match="operationId"):
        parse_openapi_operations(missing_operation_id)


def test_route_collection_normalizes_django_path_converters() -> None:
    patterns = [
        path(
            "api/v1/widgets/<uuid:item_id>/",
            GetWidgetView.as_view(),
        )
    ]

    assert collect_implemented_operations(patterns) == {
        Operation("GET", "/widgets/{item_id}"),
        Operation("HEAD", "/widgets/{item_id}"),
    }


def test_route_collection_normalizes_nested_drf_router_regexes() -> None:
    router = SimpleRouter()
    router.register("widgets", WidgetViewSet, basename="widget")
    nested_patterns = [path("billing/", include(router.urls))]

    assert collect_implemented_operations(
        [path("api/v1/", include(nested_patterns))]
    ) == {
        Operation("GET", "/billing/widgets/{pk}"),
        Operation("HEAD", "/billing/widgets/{pk}"),
    }


def test_route_collection_handles_nested_drf_lookup_regex() -> None:
    router = SimpleRouter()
    router.register("widgets", NestedRegexWidgetViewSet, basename="widget")

    assert collect_implemented_operations([path("api/v1/", include(router.urls))]) == {
        Operation("GET", "/widgets/{pk}"),
        Operation("HEAD", "/widgets/{pk}"),
    }


def test_route_collection_normalizes_default_router_format_suffixes() -> None:
    router = DefaultRouter()
    router.register("widgets", WidgetViewSet, basename="widget")

    operations = collect_implemented_operations([path("api/v1/", include(router.urls))])
    widget_operations = {
        operation for operation in operations if operation.path.startswith("/widgets")
    }

    assert widget_operations == {
        Operation("GET", "/widgets/{pk}"),
        Operation("HEAD", "/widgets/{pk}"),
    }


def test_route_collection_includes_direct_viewset_handlers() -> None:
    router = SimpleRouter()
    router.register("widgets", TraceWidgetViewSet, basename="widget")

    assert collect_implemented_operations([path("api/v1/", include(router.urls))]) == {
        Operation("GET", "/widgets"),
        Operation("HEAD", "/widgets"),
        Operation("TRACE", "/widgets"),
    }


def test_route_collection_respects_view_http_method_names() -> None:
    router = SimpleRouter()
    router.register("widgets", GetOnlyWidgetViewSet, basename="widget")

    assert collect_implemented_operations([path("api/v1/", include(router.urls))]) == {
        Operation("GET", "/widgets")
    }


def test_route_collection_respects_initkwargs_http_method_names() -> None:
    patterns = [
        path(
            "api/v1/widgets/",
            RouteMethodOverrideView.as_view(http_method_names=["get"]),
        )
    ]

    assert collect_implemented_operations(patterns) == {Operation("GET", "/widgets")}


def test_route_collection_ignores_shadowed_duplicate_routes() -> None:
    patterns = [
        path(
            "api/v1/widgets/",
            RouteMethodOverrideView.as_view(http_method_names=["get"]),
        ),
        path("api/v1/widgets/", PostUnknownView.as_view()),
    ]

    assert collect_implemented_operations(patterns) == {Operation("GET", "/widgets")}


def test_route_collection_preserves_distinct_converter_domains() -> None:
    patterns = [
        path(
            "api/v1/widgets/<uuid:item_id>/",
            GetWidgetView.as_view(),
        ),
        path(
            "api/v1/widgets/<int:item_id>/",
            PostUnknownView.as_view(),
        ),
    ]

    assert collect_implemented_operations(patterns) == {
        Operation("GET", "/widgets/{item_id}"),
        Operation("HEAD", "/widgets/{item_id}"),
        Operation("POST", "/widgets/{item_id}"),
    }


def test_route_collection_deduplicates_equivalent_compiled_matchers() -> None:
    patterns = [
        path(
            "api/v1/widgets/<int:item_id>/",
            RouteMethodOverrideView.as_view(http_method_names=["get"]),
        ),
        re_path(
            r"^api/v1/widgets/(?P<widget_id>[0-9]+)/$",
            PostUnknownView.as_view(),
        ),
    ]

    assert collect_implemented_operations(patterns) == {
        Operation("GET", "/widgets/{item_id}")
    }


def test_contract_validation_includes_head() -> None:
    contract = """openapi: 3.0.3
paths:
  /head:
    head:
      operationId: headEndpoint
      responses: {}
"""
    contract_operations = parse_openapi_operations(contract)
    implemented_operations = collect_implemented_operations(
        [path("api/v1/head/", HeadView.as_view())]
    )

    assert implemented_operations == {Operation("HEAD", "/head")}
    assert validate_implemented_operations(contract_operations, implemented_operations) == 1


def test_contract_validation_includes_explicit_options() -> None:
    contract = """openapi: 3.0.3
paths:
  /options:
    options:
      operationId: optionsEndpoint
      responses: {}
"""
    contract_operations = parse_openapi_operations(contract)
    implemented_operations = collect_implemented_operations(
        [path("api/v1/options/", OptionsView.as_view())]
    )

    assert implemented_operations == {Operation("OPTIONS", "/options")}
    assert validate_implemented_operations(contract_operations, implemented_operations) == 1


def test_contract_validation_includes_trace() -> None:
    contract = """openapi: 3.0.3
paths:
  /trace:
    trace:
      operationId: traceEndpoint
      responses: {}
"""
    contract_operations = parse_openapi_operations(contract)
    implemented_operations = collect_implemented_operations(
        [path("api/v1/trace/", TraceView.as_view())]
    )

    assert implemented_operations == {Operation("TRACE", "/trace")}
    assert validate_implemented_operations(contract_operations, implemented_operations) == 1


def test_contract_validation_canonicalizes_placeholder_names() -> None:
    contract_operations = {
        Operation("GET", "/widgets/{widget_id}"): "getWidget",
    }

    assert (
        validate_implemented_operations(
            contract_operations,
            {Operation("GET", "/widgets/{pk}")},
        )
        == 1
    )


def test_contract_validation_rejects_backend_only_operations() -> None:
    contract_operations = {
        Operation("GET", "/widgets/{item_id}"): "getWidget",
    }
    implemented_operations = collect_implemented_operations(
        [
            path(
                "api/v1/widgets/<uuid:item_id>/",
                GetWidgetView.as_view(),
            ),
            path("api/v1/backend-only/", PostUnknownView.as_view()),
        ]
    )

    with pytest.raises(ContractValidationError, match="POST /backend-only"):
        validate_implemented_operations(contract_operations, implemented_operations)


def test_contract_validation_allows_incremental_implementation() -> None:
    contract_operations = {
        Operation("GET", "/widgets/{item_id}"): "getWidget",
        Operation("POST", "/widgets"): "createWidget",
    }

    assert (
        validate_implemented_operations(
            contract_operations,
            {Operation("GET", "/widgets/{item_id}")},
        )
        == 1
    )


def test_current_backend_operations_match_pinned_openapi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = """openapi: 3.0.3
servers:
  - url: /api/v1
paths:
  /fixture:
    get:
      operationId: fixtureOperation
      responses: {}
"""
    monkeypatch.setattr(
        contract_module,
        "fetch_pinned_openapi",
        lambda _lock: document,
    )

    implemented_count, contract_count, revision = check_current_implementation()

    assert contract_count >= implemented_count
    assert contract_count > 0
    assert len(revision) == 40

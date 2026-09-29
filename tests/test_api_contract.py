from __future__ import annotations

from pathlib import Path

import pytest
from django.urls import include, path
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.routers import SimpleRouter
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

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
        Operation("GET", "/widgets/{item_id}")
    }


def test_route_collection_normalizes_nested_drf_router_regexes() -> None:
    router = SimpleRouter()
    router.register("widgets", WidgetViewSet, basename="widget")
    nested_patterns = [path("billing/", include(router.urls))]

    assert collect_implemented_operations(
        [path("api/v1/", include(nested_patterns))]
    ) == {Operation("GET", "/billing/widgets/{pk}")}


def test_route_collection_respects_view_http_method_names() -> None:
    router = SimpleRouter()
    router.register("widgets", GetOnlyWidgetViewSet, basename="widget")

    assert collect_implemented_operations([path("api/v1/", include(router.urls))]) == {
        Operation("GET", "/widgets")
    }


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


def test_current_backend_operations_match_pinned_openapi() -> None:
    implemented_count, contract_count, revision = check_current_implementation()

    assert contract_count >= implemented_count
    assert contract_count > 0
    assert len(revision) == 40

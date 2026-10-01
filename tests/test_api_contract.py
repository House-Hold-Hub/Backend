from __future__ import annotations

from pathlib import Path

import pytest
from django.core.management import call_command
from django.urls import include, path, re_path
from django.urls.resolvers import URLPattern, URLResolver
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.contract import (
    ContractCheckError,
    Operation,
    assert_implemented_operations_declared,
    collect_operations_from_patterns,
    load_contract,
    validate_contract,
)


class _WidgetView(APIView):
    def get(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})


class _ExtendedWidgetView(_WidgetView):
    def head(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})

    def options(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})

    def trace(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})


class _CrudWidgetView(_WidgetView):
    def post(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})

    def put(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})

    def patch(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})

    def delete(self, request: Request, widget_id: object) -> Response:
        return Response({"id": str(widget_id)})


def _write_contract(
    path: Path,
    *,
    server: str = "/api/v1",
    paths: str = "  {}",
) -> None:
    path.write_text(
        "openapi: 3.0.3\n"
        "info:\n"
        "  title: test\n"
        "  version: 1.0.0\n"
        "servers:\n"
        f"  - url: {server}\n"
        "paths:\n"
        f"{paths}\n",
        encoding="utf-8",
    )


def test_contract_loader_reads_server_and_operations(tmp_path: Path) -> None:
    contract_path = tmp_path / "openapi.yaml"
    _write_contract(
        contract_path,
        paths=(
            "  /widgets/{widget_id}:\n"
            "    get:\n"
            "      responses:\n"
            "        '200':\n"
            "          description: ok"
        ),
    )

    contract = load_contract(contract_path)

    assert contract.server_base_path == "/api/v1"
    assert contract.operations == frozenset({Operation("GET", "/widgets/{widget_id}")})


def test_path_include_and_uuid_placeholder_are_normalized() -> None:
    nested: list[URLPattern | URLResolver] = [
        path("<uuid:widget_id>", _WidgetView.as_view()),
    ]
    patterns: list[URLPattern | URLResolver] = [
        path("widgets/", include((nested, "widgets"))),
    ]

    operations = collect_operations_from_patterns(patterns)

    assert operations == frozenset({Operation("GET", "/widgets/{widget_id}")})


def test_explicit_extended_api_view_handlers_are_collected() -> None:
    patterns: list[URLPattern | URLResolver] = [
        path("widgets/<uuid:widget_id>", _ExtendedWidgetView.as_view()),
    ]

    operations = collect_operations_from_patterns(patterns)

    assert operations == frozenset(
        {
            Operation("GET", "/widgets/{widget_id}"),
            Operation("HEAD", "/widgets/{widget_id}"),
            Operation("OPTIONS", "/widgets/{widget_id}"),
            Operation("TRACE", "/widgets/{widget_id}"),
        }
    )


def test_crud_api_view_handlers_are_unchanged() -> None:
    patterns: list[URLPattern | URLResolver] = [
        path("widgets/<uuid:widget_id>", _CrudWidgetView.as_view()),
    ]

    operations = collect_operations_from_patterns(patterns)

    assert operations == frozenset(
        {
            Operation("GET", "/widgets/{widget_id}"),
            Operation("POST", "/widgets/{widget_id}"),
            Operation("PUT", "/widgets/{widget_id}"),
            Operation("PATCH", "/widgets/{widget_id}"),
            Operation("DELETE", "/widgets/{widget_id}"),
        }
    )


def test_regex_route_fails_closed() -> None:
    patterns: list[URLPattern | URLResolver] = [
        re_path(r"^widgets/(?P<widget_id>[^/]+)$", _WidgetView.as_view()),
    ]

    with pytest.raises(ContractCheckError, match="RegexPattern"):
        collect_operations_from_patterns(patterns)


def test_unsupported_path_converter_fails_closed() -> None:
    patterns: list[URLPattern | URLResolver] = [
        path("widgets/<path:widget_id>", _WidgetView.as_view()),
    ]

    with pytest.raises(ContractCheckError, match="path converter 'path'"):
        collect_operations_from_patterns(patterns)


def test_explicit_supported_handler_missing_from_contract_is_drift() -> None:
    patterns: list[URLPattern | URLResolver] = [
        path("widgets/<uuid:widget_id>", _ExtendedWidgetView.as_view()),
    ]
    implemented = collect_operations_from_patterns(patterns)
    contract = frozenset({Operation("GET", "/widgets/{widget_id}")})

    with pytest.raises(ContractCheckError, match="TRACE /widgets/"):
        assert_implemented_operations_declared(implemented, contract)


def test_contract_only_operations_do_not_force_placeholder_endpoints() -> None:
    implemented: frozenset[Operation] = frozenset()
    contract = frozenset({Operation("GET", "/future-resource")})

    assert_implemented_operations_declared(implemented, contract)


def test_versioned_mount_must_match_openapi_server(tmp_path: Path) -> None:
    contract_path = tmp_path / "openapi.yaml"
    _write_contract(contract_path, server="/api/v2")

    with pytest.raises(ContractCheckError, match="versioned API mount drifts"):
        validate_contract(contract_path)


def test_management_command_is_executable_against_current_empty_api(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    contract_path = tmp_path / "openapi.yaml"
    _write_contract(contract_path)

    call_command("check_api_contract", str(contract_path))

    assert "API contract check passed" in capsys.readouterr().out

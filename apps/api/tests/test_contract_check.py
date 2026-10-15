"""Contract drift detection, using small synthetic contracts (the real one lives in Documentation)."""

import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from django.urls import include, path, re_path
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api import contract
from apps.api.pagination import PageLimitPagination
from apps.api.views import ApiView

UUID_PARAM = {"name": "household_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
CSRF_REF = {"$ref": "#/components/parameters/CsrfToken"}


def base_spec(paths=None):
    return {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "servers": [{"url": "/api/v1"}],
        "security": [{"sessionAuth": []}],
        "paths": paths if paths is not None else {"/ping": {"get": {"operationId": "ping", "responses": {"200": {"description": "ok"}}}}},
        "components": {
            "securitySchemes": {"sessionAuth": {"type": "apiKey", "in": "cookie", "name": "sessionid"}},
            "parameters": {
                "CsrfToken": {"name": "X-CSRFToken", "in": "header", "required": True, "schema": {"type": "string"}},
                "Page": {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
                "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
            },
            "schemas": {
                "PageMeta": {"required": ["page", "limit", "total"]},
                "ErrorResponse": {
                    "properties": {
                        "code": {
                            "enum": [
                                "VALIDATION_ERROR", "AUTHENTICATION_ERROR", "AUTHORIZATION_ERROR",
                                "NOT_FOUND", "CONFLICT", "RATE_LIMITED", "INTERNAL_ERROR",
                            ]
                        }
                    }
                },
            },
        },
    }


def op(*params, security=None):
    result = {"operationId": "x", "parameters": list(params), "responses": {"200": {"description": "ok"}}}
    if security is not None:
        result["security"] = security
    return result


def urlconf(*patterns):
    return SimpleNamespace(urlpatterns=[path("api/v1/", include(list(patterns)))])


def codes(report):
    return sorted(f.code for f in report.findings)


class Protected(ApiView):  # GET only, session required
    def get(self, request, **kwargs):
        return Response({})


class ProtectedWrite(ApiView):  # POST only, session required
    def post(self, request, **kwargs):
        return Response({})


class ProtectedReadWrite(Protected, ProtectedWrite):
    pass


class Public(Protected):
    permission_classes = [AllowAny]


class PublicWrite(ProtectedWrite):
    permission_classes = [AllowAny]


class Paginated(Protected):
    pagination_class = PageLimitPagination


class Unpaginated(Protected):
    pagination_class = None


class RawApiView(APIView):  # bypasses ContractViewMixin
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({})


# ---- baseline ------------------------------------------------------------------------------


def test_no_implemented_operations_passes_and_counts_the_contract():
    report = contract.check(base_spec(), urlconf())
    assert report.ok and (report.implemented, report.total) == (0, 1)


def test_conforming_operations_pass():
    spec = base_spec(
        {
            "/ping": {"get": op()},
            "/open": {"post": op(CSRF_REF, security=[])},
            "/households/{household_id}": {"parameters": [UUID_PARAM], "get": op()},
        }
    )
    conf = urlconf(
        path("ping", Protected.as_view()),
        path("open", PublicWrite.as_view()),
        path("households/<uuid:household_id>", Protected.as_view()),
    )
    report = contract.check(spec, conf)
    assert report.findings == []
    assert (report.implemented, report.total) == (3, 3)


# ---- divergences are detected ----------------------------------------------------------------


def test_route_missing_from_contract_fails():
    report = contract.check(base_spec(), urlconf(path("ping", Protected.as_view()), path("extra", Protected.as_view())))
    assert codes(report) == ["OPERATION_NOT_IN_CONTRACT"]


def test_method_missing_from_contract_fails():
    report = contract.check(base_spec(), urlconf(path("ping", ProtectedReadWrite.as_view())))
    assert codes(report) == ["OPERATION_NOT_IN_CONTRACT"]
    assert "POST /ping" in str(report.findings[0])


def test_trailing_slash_is_a_divergence():
    report = contract.check(base_spec(), urlconf(path("ping/", Protected.as_view())))
    assert "OPERATION_NOT_IN_CONTRACT" in codes(report)


def test_public_in_contract_but_protected_in_code_fails():
    spec = base_spec({"/open": {"get": op(security=[])}})
    assert codes(contract.check(spec, urlconf(path("open", Protected.as_view())))) == ["SECURITY_MISMATCH"]


def test_protected_in_contract_but_public_in_code_fails():
    assert codes(contract.check(base_spec(), urlconf(path("ping", Public.as_view())))) == ["SECURITY_MISMATCH"]


def test_view_without_contract_base_class_fails_even_if_otherwise_conforming():
    spec = base_spec({"/open": {"get": op(security=[])}})
    assert codes(contract.check(spec, urlconf(path("open", RawApiView.as_view())))) == ["NOT_CONTRACT_VIEW"]


def test_unsafe_contract_operation_must_declare_csrf_header():
    spec = base_spec({"/open": {"post": op(security=[])}})
    assert codes(contract.check(spec, urlconf(path("open", PublicWrite.as_view())))) == ["CONTRACT_CSRF_MISSING"]


def test_path_converter_must_match_schema():
    spec = base_spec({"/households/{household_id}": {"parameters": [UUID_PARAM], "get": op()}})
    report = contract.check(spec, urlconf(path("households/<str:household_id>", Protected.as_view())))
    assert codes(report) == ["PATH_PARAM_TYPE"]


def test_paginated_operation_must_use_the_project_paginator():
    spec = base_spec({"/list": {"get": op({"$ref": "#/components/parameters/Page"}, {"$ref": "#/components/parameters/Limit"})}})
    assert codes(contract.check(spec, urlconf(path("list", Unpaginated.as_view())))) == ["PAGINATION"]
    assert contract.check(spec, urlconf(path("list", Paginated.as_view()))).ok


def test_unversioned_api_routes_fail():
    conf = SimpleNamespace(urlpatterns=[path("api/v2/ping", Protected.as_view()), path("api/ping", Protected.as_view())])
    assert codes(contract.check(base_spec(), conf)) == ["UNVERSIONED_API_ROUTE"] * 2


def test_api_view_mounted_outside_the_prefix_fails():
    conf = SimpleNamespace(urlpatterns=[path("health", Protected.as_view())])
    assert codes(contract.check(base_spec(), conf)) == ["API_VIEW_OUTSIDE_PREFIX"]


def test_regex_routes_cannot_be_verified_and_fail():
    assert codes(contract.check(base_spec(), urlconf(re_path(r"^ping$", Protected.as_view())))) == ["UNSUPPORTED_ROUTE"]


def test_duplicate_routes_fail():
    report = contract.check(base_spec(), urlconf(path("ping", Protected.as_view()), path("ping", Protected.as_view())))
    assert "DUPLICATE_ROUTE" in codes(report)


def test_view_with_unevaluable_permissions_fails_instead_of_passing():
    class Broken(Protected):
        def get_permissions(self):
            raise RuntimeError("cannot build permissions")

    assert codes(contract.check(base_spec(), urlconf(path("ping", Broken.as_view())))) == ["PROBE_FAILED"]


def test_protected_view_without_session_authentication_fails():
    class NoAuth(Protected):
        authentication_classes = []

    assert "SESSION_AUTH_MISSING" in codes(contract.check(base_spec(), urlconf(path("ping", NoAuth.as_view()))))


# ---- incremental validation does not mask future errors ---------------------------------------


def test_unimplemented_operations_are_not_failures_but_do_not_hide_real_drift():
    many = {f"/future{i}": {"get": op()} for i in range(10)}
    spec = base_spec({"/ping": {"get": op()}, **many})
    assert contract.check(spec, urlconf(path("ping", Protected.as_view()))).ok

    report = contract.check(spec, urlconf(path("ping", Public.as_view()), path("future3", Protected.as_view())))
    assert codes(report) == ["SECURITY_MISMATCH"]
    assert (report.implemented, report.total) == (2, 11)


# ---- foundation drift ---------------------------------------------------------------------------


def mutate(spec, fn):
    spec = copy.deepcopy(spec)
    fn(spec)
    return spec


@pytest.mark.parametrize(
    "code, change",
    [
        ("SERVER_URL", lambda s: s.__setitem__("servers", [{"url": "/api/v2"}])),
        ("ROOT_SECURITY", lambda s: s.__setitem__("security", [])),
        ("SESSION_COOKIE", lambda s: s["components"]["securitySchemes"]["sessionAuth"].__setitem__("name", "other")),
        ("CSRF_HEADER", lambda s: s["components"]["parameters"]["CsrfToken"].__setitem__("name", "X-Other")),
        ("PAGINATION_PARAM", lambda s: s["components"]["parameters"]["Limit"]["schema"].__setitem__("maximum", 500)),
        ("PAGINATION_PARAM", lambda s: s["components"]["parameters"]["Page"]["schema"].__setitem__("default", 2)),
        ("PAGE_META", lambda s: s["components"]["schemas"]["PageMeta"].__setitem__("required", ["page", "limit"])),
        ("ERROR_CODES", lambda s: s["components"]["schemas"]["ErrorResponse"]["properties"]["code"]["enum"].append("TEAPOT")),
        ("ERROR_CODES", lambda s: s["components"]["schemas"]["ErrorResponse"]["properties"]["code"]["enum"].remove("CONFLICT")),
    ],
)
def test_foundation_drift_is_detected(code, change):
    assert codes(contract.check(mutate(base_spec(), change), urlconf())) == [code]


# ---- pinned revision -------------------------------------------------------------------------


def write_contract(tmp_path, spec=None, **pin_overrides):
    raw = yaml.safe_dump(spec if spec is not None else base_spec()).encode()
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_bytes(raw)
    pin = {"repository": "o/Documentation", "commit": "a" * 40, "path": "api/openapi.yaml", "sha256": hashlib.sha256(raw).hexdigest()}
    pin.update(pin_overrides)
    pin_file = tmp_path / "pin.json"
    pin_file.write_text(json.dumps(pin))
    return spec_file, pin_file


def test_committed_pin_is_well_formed():
    pin = contract.load_pin()
    assert pin.repository == "House-Hold-Hub/Documentation" and pin.path == "api/openapi.yaml"


def test_contract_matching_the_pin_loads(tmp_path):
    spec_file, pin_file = write_contract(tmp_path)
    assert contract.load_contract(spec_file, contract.load_pin(pin_file))["openapi"] == "3.0.3"


def test_contract_not_matching_the_pinned_revision_is_refused(tmp_path):
    spec_file, pin_file = write_contract(tmp_path, sha256="0" * 64)
    with pytest.raises(contract.ContractError, match="pinned revision"):
        contract.load_contract(spec_file, contract.load_pin(pin_file))


@pytest.mark.parametrize("override", [{"commit": "main"}, {"sha256": "abc"}])
def test_pin_must_name_an_exact_revision(tmp_path, override):
    _, pin_file = write_contract(tmp_path, **override)
    with pytest.raises(contract.ContractError):
        contract.load_pin(pin_file)


def test_missing_pin_or_spec_is_an_error(tmp_path):
    with pytest.raises(contract.ContractError):
        contract.load_pin(tmp_path / "absent.json")
    _, pin_file = write_contract(tmp_path)
    with pytest.raises(contract.ContractError):
        contract.load_contract(tmp_path / "absent.yaml", contract.load_pin(pin_file))


def test_contract_without_operations_is_refused_not_passed(tmp_path):
    spec_file, pin_file = write_contract(tmp_path, base_spec({}))
    with pytest.raises(contract.ContractError, match="vacuous"):
        contract.load_contract(spec_file, contract.load_pin(pin_file))


# ---- management command ------------------------------------------------------------------------


def test_command_passes_when_nothing_diverges(tmp_path, capsys):
    spec_file, pin_file = write_contract(tmp_path)
    with override_settings(ROOT_URLCONF="apps.api.tests.empty_urls"):
        call_command("check_api_contract", spec=str(spec_file), pin=str(pin_file))
    assert "0/1 operations implemented" in capsys.readouterr().out


def test_command_fails_on_drift(tmp_path):
    spec_file, pin_file = write_contract(tmp_path)
    with override_settings(ROOT_URLCONF="apps.api.tests.support"):  # routes that are not in this contract
        with pytest.raises(CommandError, match="divergence"):
            call_command("check_api_contract", spec=str(spec_file), pin=str(pin_file))


def test_command_fails_when_contract_is_not_the_pinned_revision(tmp_path):
    spec_file, pin_file = write_contract(tmp_path, sha256="1" * 64)
    with pytest.raises(CommandError, match="pinned revision"):
        call_command("check_api_contract", spec=str(spec_file), pin=str(pin_file))


@pytest.mark.skipif(not os.environ.get("HOUSEHOLDHUB_OPENAPI_SPEC"), reason="set HOUSEHOLDHUB_OPENAPI_SPEC to the pinned Documentation api/openapi.yaml")
def test_project_conforms_to_the_pinned_documentation_contract():
    call_command("check_api_contract", spec=str(Path(os.environ["HOUSEHOLDHUB_OPENAPI_SPEC"])))

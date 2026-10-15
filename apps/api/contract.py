"""Drift check between the implemented ``/api/v1`` operations and the Documentation OpenAPI contract.

The Documentation repository owns ``api/openapi.yaml`` (ADR-014). Backend stores no copy of it:
``contract/documentation-revision.json`` pins the Documentation commit and the SHA-256 of the
contract file, and the check refuses to run against any other bytes. Bumping the pin is a
deliberate Backend change.

Validation is incremental without an allowlist or baseline: implemented operations are
*discovered* from the live URLconf, so a route that is not in the contract, or that diverges
from it, fails the check from the moment it exists. Operations the contract defines but the
Backend has not implemented yet are only counted. Besides per-operation checks, the foundation
the contract depends on (server prefix, session cookie, CSRF header, pagination, error codes)
is always verified.
"""

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.http import Http404
from django.urls import URLPattern, URLResolver, get_resolver
from django.urls.resolvers import RegexPattern
from rest_framework.exceptions import APIException
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from . import pagination
from .authentication import ApiSessionAuthentication
from .errors import ErrorCode
from .views import ContractViewMixin

API_PREFIX = "api/v1"
HTTP_METHODS = ("get", "post", "put", "patch", "delete")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PIN_PATH = Path(settings.BASE_DIR) / "contract" / "documentation-revision.json"
_ROUTE_PARAM = re.compile(r"<(?:(?P<converter>[^>:]+):)?(?P<name>[^>]+)>")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ContractError(Exception):
    """The contract or its pin cannot be used (distinct from drift findings)."""


@dataclass(frozen=True)
class Finding:
    code: str
    subject: str
    message: str

    def __str__(self):
        return f"[{self.code}] {self.subject}: {self.message}"


@dataclass
class Report:
    findings: list = field(default_factory=list)
    implemented: int = 0
    total: int = 0

    @property
    def ok(self):
        return not self.findings

    def add(self, code, subject, message):
        self.findings.append(Finding(code, subject, message))


@dataclass(frozen=True)
class Pin:
    repository: str
    commit: str
    path: str
    sha256: str


def load_pin(path=PIN_PATH):
    try:
        data = json.loads(Path(path).read_text())
        pin = Pin(**{key: data[key] for key in ("repository", "commit", "path", "sha256")})
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ContractError(f"Unreadable contract pin {path}: {exc}") from exc
    if not _COMMIT.match(pin.commit) or not _SHA256.match(pin.sha256):
        raise ContractError(f"Contract pin {path} needs a full 40-hex commit and a 64-hex sha256.")
    return pin


def load_contract(spec_path, pin):
    """Parse the contract after verifying it is byte-identical to the pinned revision."""
    import yaml

    try:
        raw = Path(spec_path).read_bytes()
    except OSError as exc:
        raise ContractError(f"Cannot read contract {spec_path}: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin.sha256:
        raise ContractError(
            f"{spec_path} does not match the pinned revision {pin.repository}@{pin.commit[:12]} "
            f"(sha256 {digest} != {pin.sha256}). Check out that Documentation commit, or update "
            "contract/documentation-revision.json deliberately."
        )
    try:
        spec = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ContractError(f"Contract is not valid YAML: {exc}") from exc
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3.0"):
        raise ContractError("Contract is not an OpenAPI 3.0 document.")
    if not contract_operations(spec):
        raise ContractError("Contract defines no operations; refusing a vacuous pass.")
    return spec


def resolve(spec, node):
    """Resolve a local ``$ref``; external references are not supported by the contract."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            raise ContractError(f"Unsupported non-local $ref {ref!r}.")
        target = spec
        for part in ref[2:].split("/"):
            target = target[part]
        node = target
        seen += 1
        if seen > 20:
            raise ContractError(f"$ref loop at {ref!r}.")
    return node


def contract_operations(spec):
    """Map ``(METHOD, path)`` to the operation, with path-level parameters merged in."""
    operations = {}
    for path, item in (spec.get("paths") or {}).items():
        shared = item.get("parameters", [])
        for method in HTTP_METHODS:
            if method in item:
                op = dict(item[method])
                op["parameters"] = [resolve(spec, p) for p in shared + item[method].get("parameters", [])]
                operations[(method.upper(), path)] = op
    return operations


# --- implementation discovery -------------------------------------------------------------


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    route: str
    callback: object
    converters: dict


def _view_class(callback):
    return getattr(callback, "cls", None) or getattr(callback, "view_class", None)


def _handled_methods(callback):
    actions = getattr(callback, "actions", None)
    if actions:
        return {method.upper() for method in actions}
    cls = _view_class(callback)
    if cls is None:
        return set()
    return {m.upper() for m in cls.http_method_names if m not in ("options", "head") and hasattr(cls, m)}


def _walk(patterns, prefix=""):
    for pattern in patterns:
        route = prefix + str(pattern.pattern)
        if isinstance(pattern, URLResolver):
            yield from _walk(pattern.url_patterns, route)
        elif isinstance(pattern, URLPattern):
            yield route, pattern


def discover(urlconf, report):
    """Return the implemented routes below ``/api/v1`` and flag anything unverifiable."""
    routes: list[Any] = []
    resolver = get_resolver(urlconf) if isinstance(urlconf, str) else URLResolver(RegexPattern(r"^/"), urlconf)
    for route, pattern in _walk(resolver.url_patterns):
        callback = pattern.callback
        cls = _view_class(callback)
        in_prefix = route == API_PREFIX or route.startswith(API_PREFIX + "/")
        if not in_prefix:
            if route.startswith("api/"):
                report.add("UNVERSIONED_API_ROUTE", f"/{route}", f"API routes must live under /{API_PREFIX}/.")
            elif cls is not None and issubclass(cls, APIView):
                report.add("API_VIEW_OUTSIDE_PREFIX", f"/{route}", f"DRF views must be mounted under /{API_PREFIX}/.")
            continue
        if not hasattr(pattern.pattern, "converters") or "^" in route or "(?P<" in route:
            report.add("UNSUPPORTED_ROUTE", f"/{route}", "Only path() routes can be verified against the contract.")
            continue
        path = _ROUTE_PARAM.sub(lambda m: "{" + m["name"] + "}", route[len(API_PREFIX) :]) or "/"
        converters = {m["name"]: m["converter"] or "str" for m in _ROUTE_PARAM.finditer(route)}
        methods = _handled_methods(callback)
        if not methods:
            report.add("NO_HTTP_METHODS", path, "The route handles no HTTP method.")
        routes.extend(Route(method, path, route, callback, converters) for method in sorted(methods))
    return routes


# --- checks ---------------------------------------------------------------------------------


def _anonymous_allowed(callback, method, path_params):
    """Probe the view's permissions with an anonymous caller. ``True`` means public."""
    cls = _view_class(callback)
    view = cls(**getattr(callback, "initkwargs", {}))
    actions = getattr(callback, "actions", None) or {}
    view.action_map = actions
    view.action = actions.get(method.lower())
    view.args = ()
    view.kwargs = {name: "00000000-0000-0000-0000-000000000000" for name in path_params}
    request = Request(APIRequestFactory().generic(method, "/"), authenticators=[])
    request.user = AnonymousUser()
    view.request = request
    for permission in view.get_permissions():
        try:
            if not permission.has_permission(request, view):
                return False
        except (APIException, Http404):
            return False
    return True


def _check_operation(spec, report, route, op):
    subject = f"{route.method} {route.path}"
    cls = _view_class(route.callback)

    if not issubclass(cls, ContractViewMixin):
        report.add("NOT_CONTRACT_VIEW", subject, "Views must extend apps.api.views.ContractViewMixin (CSRF/error semantics).")

    for param in op["parameters"]:
        if param.get("in") == "path":
            schema = resolve(spec, param.get("schema", {}))
            converter = route.converters.get(param["name"])
            if converter is None:
                continue
            expected = {"uuid": "uuid"}.get(schema.get("format"), {"integer": "int"}.get(schema.get("type")))
            if expected and converter != expected:
                report.add("PATH_PARAM_TYPE", subject, f"'{param['name']}' must use the '{expected}' converter, found '{converter}'.")

    contract_public = op.get("security") == []
    try:
        public = _anonymous_allowed(route.callback, route.method, route.converters)
    except Exception as exc:  # an uninspectable view must fail, never pass
        report.add("PROBE_FAILED", subject, f"Cannot evaluate permissions for an anonymous caller: {exc!r}")
        public = None
    if public is not None and public != contract_public:
        report.add(
            "SECURITY_MISMATCH",
            subject,
            "Contract declares the operation public (security: [])." if contract_public
            else "Contract requires a session; the view admits anonymous callers.",
        )
    if not contract_public and not any(issubclass(a, ApiSessionAuthentication) for a in cls.authentication_classes):
        report.add("SESSION_AUTH_MISSING", subject, "Protected operations need ApiSessionAuthentication.")

    if route.method not in SAFE_METHODS and not any(
        p.get("in") == "header" and p.get("name") == "X-CSRFToken" for p in op["parameters"]
    ):
        report.add("CONTRACT_CSRF_MISSING", subject, "Unsafe contract operation does not declare the X-CSRFToken header.")

    query = {p["name"] for p in op["parameters"] if p.get("in") == "query"}
    if {"page", "limit"} <= query and not (
        isinstance(getattr(cls, "pagination_class", None), type)
        and issubclass(cls.pagination_class, pagination.PageLimitPagination)
    ):
        report.add("PAGINATION", subject, "Paginated contract operation must use PageLimitPagination.")


def _check_foundation(spec, report):
    """Cross-cutting wire conventions the contract defines and the Backend configuration must match."""
    subject = "foundation"
    servers = [s.get("url") for s in spec.get("servers", [])]
    if servers != [f"/{API_PREFIX}"]:
        report.add("SERVER_URL", subject, f"Contract servers {servers} != ['/{API_PREFIX}'].")

    components = spec.get("components", {})
    scheme = components.get("securitySchemes", {}).get("sessionAuth", {})
    if spec.get("security") != [{"sessionAuth": []}]:
        report.add("ROOT_SECURITY", subject, "Contract root security must be sessionAuth.")
    if (scheme.get("type"), scheme.get("in"), scheme.get("name")) != ("apiKey", "cookie", settings.SESSION_COOKIE_NAME):
        report.add("SESSION_COOKIE", subject, f"sessionAuth must be the '{settings.SESSION_COOKIE_NAME}' cookie, contract: {scheme}.")

    header = components.get("parameters", {}).get("CsrfToken", {})
    expected_meta = "HTTP_" + str(header.get("name", "")).upper().replace("-", "_")
    if header.get("in") != "header" or expected_meta != settings.CSRF_HEADER_NAME:
        report.add("CSRF_HEADER", subject, f"CSRF header {header.get('name')!r} does not match CSRF_HEADER_NAME={settings.CSRF_HEADER_NAME}.")

    for name, default, maximum in (("Page", pagination.DEFAULT_PAGE, None), ("Limit", pagination.DEFAULT_LIMIT, pagination.MAX_LIMIT)):
        param = components.get("parameters", {}).get(name, {})
        schema = param.get("schema", {})
        if (param.get("in"), schema.get("minimum"), schema.get("default"), schema.get("maximum")) != ("query", 1, default, maximum):
            report.add("PAGINATION_PARAM", subject, f"Parameter {name} differs from the paginator (min 1, default {default}, max {maximum}).")
    if tuple(components.get("schemas", {}).get("PageMeta", {}).get("required", [])) != pagination.META_FIELDS:
        report.add("PAGE_META", subject, f"PageMeta.required must be {list(pagination.META_FIELDS)}.")

    codes = set(components.get("schemas", {}).get("ErrorResponse", {}).get("properties", {}).get("code", {}).get("enum", []))
    if codes != {str(code) for code in ErrorCode}:
        report.add("ERROR_CODES", subject, f"ErrorResponse.code enum {sorted(codes)} != backend ErrorCode {sorted(map(str, ErrorCode))}.")


def check(spec, urlconf=None):
    """Compare the live URLconf with ``spec`` and return a :class:`Report`."""
    report = Report()
    urlconf = urlconf if urlconf is not None else settings.ROOT_URLCONF
    operations = contract_operations(spec)
    report.total = len(operations)
    _check_foundation(spec, report)

    routes = discover(urlconf, report)
    for (method, path), count in Counter((r.method, r.path) for r in routes).items():
        if count > 1:
            report.add("DUPLICATE_ROUTE", f"{method} {path}", "Routed more than once; later routes are unreachable.")
    implemented = set()
    for route in routes:
        op = operations.get((route.method, route.path))
        if op is None:
            report.add("OPERATION_NOT_IN_CONTRACT", f"{route.method} {route.path}", "Not defined by the contract.")
            continue
        implemented.add((route.method, route.path))
        _check_operation(spec, report, route, op)
    report.implemented = len(implemented)
    return report

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from django.urls.resolvers import RoutePattern, URLPattern, URLResolver, get_resolver
from rest_framework.views import APIView

_API_URLCONF = "api.urls"
_SUPPORTED_CONVERTERS = frozenset({"str", "int", "slug", "uuid"})
_OPENAPI_OPERATION_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
_OPENAPI_PATH_ITEM_METADATA = frozenset(
    {"$ref", "summary", "description", "servers", "parameters"}
)
_ROUTE_PARAMETER = re.compile(
    r"<(?:(?P<converter>[A-Za-z_][A-Za-z0-9_]*):)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)>"
)


class ContractCheckError(RuntimeError):
    """Raised when the Backend cannot be conservatively compared with OpenAPI."""


@dataclass(frozen=True, order=True)
class Operation:
    method: str
    path: str


@dataclass(frozen=True)
class ContractDefinition:
    server_base_path: str
    operations: frozenset[Operation]


@dataclass(frozen=True)
class ContractCheckResult:
    implemented: frozenset[Operation]
    contract: frozenset[Operation]


def _mapping(value: object, context: str) -> Mapping[object, object]:
    if not isinstance(value, Mapping):
        raise ContractCheckError(f"{context} must be a mapping")
    return value


def load_contract(contract_path: Path) -> ContractDefinition:
    try:
        source = contract_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractCheckError(f"cannot read OpenAPI contract {contract_path}: {exc}") from exc

    try:
        document: object = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ContractCheckError(f"cannot parse OpenAPI contract {contract_path}: {exc}") from exc

    root = _mapping(document, "OpenAPI document")
    servers = root.get("servers")
    if not isinstance(servers, list) or len(servers) != 1:
        raise ContractCheckError("OpenAPI must declare exactly one server for Backend comparison")

    server = _mapping(servers[0], "OpenAPI server")
    server_url = server.get("url")
    if not isinstance(server_url, str) or not server_url.startswith("/"):
        raise ContractCheckError("OpenAPI server URL must be a same-origin absolute path")
    if any(token in server_url for token in ("://", "{", "}", "?", "#")):
        raise ContractCheckError(f"unsupported OpenAPI server URL: {server_url!r}")

    paths = _mapping(root.get("paths"), "OpenAPI paths")
    operations: set[Operation] = set()

    for raw_path, raw_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            raise ContractCheckError(f"unsupported OpenAPI path key: {raw_path!r}")

        item = _mapping(raw_item, f"OpenAPI path item {raw_path}")
        for raw_key in item:
            if not isinstance(raw_key, str):
                raise ContractCheckError(f"non-string key in OpenAPI path item {raw_path}")

            key = raw_key.lower()
            if key in _OPENAPI_OPERATION_METHODS:
                operations.add(Operation(key.upper(), raw_path))
            elif key in _OPENAPI_PATH_ITEM_METADATA or key.startswith("x-"):
                continue
            else:
                raise ContractCheckError(
                    f"unsupported OpenAPI path-item key {raw_key!r} at {raw_path}"
                )

    return ContractDefinition(server_base_path=server_url, operations=frozenset(operations))


def _urlconf_name(resolver: URLResolver) -> str | None:
    urlconf = resolver.urlconf_name
    if isinstance(urlconf, str):
        return urlconf
    name = getattr(urlconf, "__name__", None)
    return name if isinstance(name, str) else None


def _find_api_resolver() -> URLResolver:
    matches = [
        entry
        for entry in get_resolver().url_patterns
        if isinstance(entry, URLResolver) and _urlconf_name(entry) == _API_URLCONF
    ]
    if len(matches) != 1:
        raise ContractCheckError(
            f"expected exactly one top-level include({_API_URLCONF!r}); found {len(matches)}"
        )
    return matches[0]


def _route_text(pattern: object) -> str:
    if not isinstance(pattern, RoutePattern):
        raise ContractCheckError(
            f"unsupported Django routing construct {type(pattern).__name__}; "
            "use path()-based routes (DRF routers must use use_regex_path=False)"
        )
    return str(pattern)


def _normalize_route_fragment(route: str) -> str:
    parts: list[str] = []
    cursor = 0

    for match in _ROUTE_PARAMETER.finditer(route):
        literal = route[cursor : match.start()]
        if "<" in literal or ">" in literal:
            raise ContractCheckError(f"unsupported Django route syntax: {route!r}")
        parts.append(literal)

        converter = match.group("converter") or "str"
        if converter not in _SUPPORTED_CONVERTERS:
            raise ContractCheckError(
                f"unsupported Django path converter {converter!r} in route {route!r}"
            )
        parts.append("{" + match.group("name") + "}")
        cursor = match.end()

    tail = route[cursor:]
    if "<" in tail or ">" in tail:
        raise ContractCheckError(f"unsupported Django route syntax: {route!r}")
    parts.append(tail)

    normalized = "".join(parts)
    if normalized.startswith("/"):
        raise ContractCheckError(f"Django routes must not start with '/': {route!r}")
    return normalized


def _django_api_base_path(resolver: URLResolver) -> str:
    route = _normalize_route_fragment(_route_text(resolver.pattern))
    if not route or not route.endswith("/") or "{" in route:
        raise ContractCheckError(
            "the top-level api.urls include must be a static path prefix ending in '/'"
        )
    return "/" + route[:-1]


def _methods_for_callback(callback: object) -> frozenset[str]:
    actions = getattr(callback, "actions", None)
    if actions is not None:
        if not isinstance(actions, Mapping):
            raise ContractCheckError("DRF ViewSet callback actions must be a mapping")

        view_class = getattr(callback, "cls", None)
        if view_class is None:
            view_class = getattr(callback, "view_class", None)
        if not isinstance(view_class, type) or not issubclass(view_class, APIView):
            raise ContractCheckError("DRF ViewSet callback has no supported view class")

        methods: set[str] = set()
        for raw_method in actions:
            if not isinstance(raw_method, str):
                raise ContractCheckError("DRF ViewSet action methods must be strings")
            method = raw_method.lower()
            if method not in _OPENAPI_OPERATION_METHODS:
                raise ContractCheckError(
                    f"unsupported HTTP method in DRF ViewSet: {raw_method!r}"
                )
            if method in view_class.http_method_names:
                methods.add(method.upper())

        if not methods:
            raise ContractCheckError("DRF ViewSet callback has no explicit HTTP method mappings")
        return frozenset(methods)

    view_class = getattr(callback, "cls", None)
    if view_class is None:
        view_class = getattr(callback, "view_class", None)

    if not isinstance(view_class, type) or not issubclass(view_class, APIView):
        raise ContractCheckError(
            "API route callback is not a supported DRF APIView/@api_view/ViewSet callback"
        )

    implementation_mro = view_class.__mro__[: view_class.__mro__.index(APIView)]
    methods = {
        method.upper()
        for method in _OPENAPI_OPERATION_METHODS
        if method in view_class.http_method_names
        and any(method in owner.__dict__ for owner in implementation_mro)
        and callable(getattr(view_class, method, None))
    }
    if not methods:
        raise ContractCheckError("DRF APIView route has no supported explicit HTTP handlers")
    return frozenset(methods)


def collect_operations_from_patterns(
    patterns: Sequence[URLPattern | URLResolver],
    prefix: str = "",
) -> frozenset[Operation]:
    operations: set[Operation] = set()

    for entry in patterns:
        fragment = _normalize_route_fragment(_route_text(entry.pattern))
        route = prefix + fragment

        if isinstance(entry, URLResolver):
            operations.update(collect_operations_from_patterns(entry.url_patterns, route))
            continue

        if not isinstance(entry, URLPattern):
            raise ContractCheckError(f"unsupported URL entry type: {type(entry).__name__}")

        path = "/" + route if route else "/"
        for method in _methods_for_callback(entry.callback):
            operations.add(Operation(method, path))

    return frozenset(operations)


def collect_implemented_operations(expected_base_path: str) -> frozenset[Operation]:
    resolver = _find_api_resolver()
    configured_base_path = _django_api_base_path(resolver)
    if configured_base_path != expected_base_path:
        raise ContractCheckError(
            "versioned API mount drifts from OpenAPI server URL: "
            f"Django={configured_base_path!r}, OpenAPI={expected_base_path!r}"
        )
    return collect_operations_from_patterns(resolver.url_patterns)


def assert_implemented_operations_declared(
    implemented: frozenset[Operation],
    contract: frozenset[Operation],
) -> None:
    drift = sorted(implemented - contract)
    if not drift:
        return

    details = "\n".join(f"  - {operation.method} {operation.path}" for operation in drift)
    raise ContractCheckError(
        "Backend exposes operations not declared by the canonical OpenAPI contract:\n" + details
    )


def validate_contract(contract_path: Path) -> ContractCheckResult:
    definition = load_contract(contract_path)
    implemented = collect_implemented_operations(definition.server_base_path)
    assert_implemented_operations_declared(implemented, definition.operations)
    return ContractCheckResult(implemented=implemented, contract=definition.operations)

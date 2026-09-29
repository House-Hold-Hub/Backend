from __future__ import annotations

import hashlib
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.request import urlopen

import yaml
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.views import APIView

API_PREFIX = "api/v1/"
CANONICAL_CONTRACT_REPOSITORY = "House-Hold-Hub/Documentation"
CANONICAL_CONTRACT_PATH = "api/openapi.yaml"
HTTP_METHODS = ("get", "head", "options", "post", "put", "patch", "delete", "trace")
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK_PATH = ROOT / "api" / "openapi-contract.lock.toml"

_DJANGO_CONVERTER_PATTERN = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")
_DRF_NAMED_GROUP_NAME_PATTERN = re.compile(r"\(\?P<[A-Za-z_]\w*>")
_URL_LITERAL_ESCAPE_PATTERN = re.compile(
    r"\\([.\-_~:@!$&'()*+,;=/])"
)
_PATH_PLACEHOLDER_PATTERN = re.compile(r"\{[^{}]+\}")
_DRF_FORMAT_SUFFIX = r"\.{format}/?"
_DRF_PATH_FORMAT_SUFFIX = "<drf_format_suffix:format>"
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ContractValidationError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Operation:
    method: str
    path: str


@dataclass(frozen=True)
class ContractLock:
    repository: str
    revision: str
    path: str
    git_blob_sha: str

    @property
    def raw_url(self) -> str:
        return (
            f"https://raw.githubusercontent.com/{self.repository}/"
            f"{self.revision}/{self.path}"
        )


def _require_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ContractValidationError(f"Contract lock field {key!r} must be a non-empty string.")
    return value


def load_contract_lock(path: Path | None = None) -> ContractLock:
    lock_path = path or DEFAULT_LOCK_PATH
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    contract_data = data.get("contract")
    if not isinstance(contract_data, dict):
        raise ContractValidationError("Contract lock must contain a [contract] table.")

    contract = cast(Mapping[str, object], contract_data)
    lock = ContractLock(
        repository=_require_string(contract, "repository"),
        revision=_require_string(contract, "revision"),
        path=_require_string(contract, "path"),
        git_blob_sha=_require_string(contract, "git_blob_sha"),
    )

    if lock.repository != CANONICAL_CONTRACT_REPOSITORY:
        raise ContractValidationError(
            "Contract lock must reference House-Hold-Hub/Documentation."
        )
    if lock.path != CANONICAL_CONTRACT_PATH:
        raise ContractValidationError("Contract lock must reference api/openapi.yaml.")
    if not _SHA_PATTERN.fullmatch(lock.revision):
        raise ContractValidationError("Contract revision must be a full 40-character commit SHA.")
    if not _SHA_PATTERN.fullmatch(lock.git_blob_sha):
        raise ContractValidationError("Contract blob SHA must be a full 40-character Git SHA.")

    return lock


def git_blob_sha(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode()
    return hashlib.sha1(header + payload).hexdigest()


def fetch_pinned_openapi(lock: ContractLock) -> str:
    with urlopen(lock.raw_url, timeout=15) as response:
        payload = response.read()

    actual_blob_sha = git_blob_sha(payload)
    if actual_blob_sha != lock.git_blob_sha:
        raise ContractValidationError(
            "Pinned OpenAPI content does not match the checked-in Git blob SHA: "
            f"expected {lock.git_blob_sha}, got {actual_blob_sha}."
        )

    return payload.decode("utf-8")


def _load_openapi(document: str) -> Mapping[str, object]:
    try:
        raw_document = yaml.safe_load(document)
    except yaml.YAMLError as exc:
        raise ContractValidationError("The pinned OpenAPI document is invalid YAML.") from exc

    if not isinstance(raw_document, dict):
        raise ContractValidationError("The pinned OpenAPI document must be a mapping.")

    return cast(Mapping[str, object], raw_document)


def parse_openapi_operations(document: str) -> dict[Operation, str]:
    openapi = _load_openapi(document)
    raw_paths = openapi.get("paths")
    if not isinstance(raw_paths, dict) or not raw_paths:
        raise ContractValidationError("The pinned OpenAPI document contains no paths.")

    operations: dict[Operation, str] = {}
    for raw_path, raw_path_item in raw_paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            raise ContractValidationError("Every OpenAPI path must be an absolute API path.")
        if not isinstance(raw_path_item, dict):
            raise ContractValidationError(f"OpenAPI path {raw_path!r} must be a mapping.")

        path_item = cast(Mapping[str, object], raw_path_item)
        for method in HTTP_METHODS:
            raw_operation = path_item.get(method)
            if raw_operation is None:
                continue
            if not isinstance(raw_operation, dict):
                raise ContractValidationError(
                    f"OpenAPI operation {method.upper()} {raw_path} must be a mapping."
                )

            operation = cast(Mapping[str, object], raw_operation)
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise ContractValidationError(
                    f"OpenAPI operation {method.upper()} {raw_path} must declare operationId."
                )

            key = Operation(method.upper(), raw_path)
            if key in operations:
                raise ContractValidationError(
                    f"Duplicate contract operation: {key.method} {key.path}."
                )
            operations[key] = operation_id

    if not operations:
        raise ContractValidationError("The pinned OpenAPI document contains no operations.")
    return operations


def contract_declares_api_v1(document: str) -> bool:
    openapi = _load_openapi(document)
    raw_servers = openapi.get("servers")
    if not isinstance(raw_servers, list):
        return False

    for raw_server in raw_servers:
        if not isinstance(raw_server, dict):
            continue
        server = cast(Mapping[str, object], raw_server)
        if server.get("url") == "/api/v1":
            return True
    return False


def _replace_drf_named_groups(route: str) -> str:
    parts: list[str] = []
    index = 0

    while True:
        start = route.find("(?P<", index)
        if start < 0:
            parts.append(route[index:])
            return "".join(parts)

        parts.append(route[index:start])
        name_end = route.find(">", start + 4)
        if name_end < 0:
            raise ContractValidationError("Malformed DRF named route group.")

        name = route[start + 4 : name_end]
        depth = 1
        cursor = name_end + 1
        escaped = False
        in_character_class = False

        while cursor < len(route):
            character = route[cursor]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "[":
                in_character_class = True
            elif character == "]" and in_character_class:
                in_character_class = False
            elif not in_character_class:
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                    if depth == 0:
                        break
            cursor += 1

        if depth != 0:
            raise ContractValidationError("Malformed DRF named route group.")

        parts.append(f"{{{name}}}")
        index = cursor + 1


def _replace_positional_groups(route: str) -> str:
    parts: list[str] = []
    index = 0
    placeholder_index = 1
    escaped = False
    in_character_class = False

    while index < len(route):
        character = route[index]
        if escaped:
            parts.append(character)
            escaped = False
            index += 1
            continue
        if character == "\\":
            parts.append(character)
            escaped = True
            index += 1
            continue
        if character == "[":
            in_character_class = True
        elif character == "]" and in_character_class:
            in_character_class = False

        if (
            character == "("
            and not in_character_class
            and not route.startswith("(?", index)
        ):
            depth = 1
            cursor = index + 1
            nested_escaped = False
            nested_character_class = False
            while cursor < len(route):
                nested = route[cursor]
                if nested_escaped:
                    nested_escaped = False
                elif nested == "\\":
                    nested_escaped = True
                elif nested == "[":
                    nested_character_class = True
                elif nested == "]" and nested_character_class:
                    nested_character_class = False
                elif not nested_character_class:
                    if nested == "(":
                        depth += 1
                    elif nested == ")":
                        depth -= 1
                        if depth == 0:
                            break
                cursor += 1
            if depth != 0:
                raise ContractValidationError("Malformed positional route group.")

            parts.append(f"{{arg{placeholder_index}}}")
            placeholder_index += 1
            index = cursor + 1
            continue

        parts.append(character)
        index += 1

    return "".join(parts)


def _unescape_url_literals(route: str) -> str:
    return _URL_LITERAL_ESCAPE_PATTERN.sub(r"\1", route)


def _normalize_api_route(route: str) -> str | None:
    if not route.startswith(API_PREFIX):
        return None

    relative_route = route[len(API_PREFIX) :].strip()
    relative_route = relative_route.removeprefix("^").removesuffix("$").strip("/")
    normalized = _replace_drf_named_groups(relative_route)
    normalized = _replace_positional_groups(normalized)
    if normalized.endswith(_DRF_FORMAT_SUFFIX):
        normalized = normalized[: -len(_DRF_FORMAT_SUFFIX)]
    elif normalized.endswith(_DRF_PATH_FORMAT_SUFFIX):
        normalized = normalized[: -len(_DRF_PATH_FORMAT_SUFFIX)]
    normalized = _DJANGO_CONVERTER_PATTERN.sub(r"{\1}", normalized)
    normalized = _unescape_url_literals(normalized)
    return "/" + normalized if normalized else "/"


def _pattern_match_signature(
    pattern: Any,
) -> tuple[str, tuple[tuple[int, type[Any]], ...], int]:
    compiled_regex = pattern.regex
    regex = compiled_regex.pattern
    regex = regex.removeprefix("^").removesuffix(r"\Z").removesuffix("$")
    canonical_regex = _DRF_NAMED_GROUP_NAME_PATTERN.sub("(", regex)

    converters = getattr(pattern, "converters", {})
    custom_converter_bindings = tuple(
        (compiled_regex.groupindex[name], type(converter))
        for name, converter in converters.items()
        if type(converter).__module__ != "django.urls.converters"
    )
    return canonical_regex, custom_converter_bindings, compiled_regex.groups


def _callback_methods(callback: Any) -> set[str]:
    view_class = getattr(callback, "cls", None)
    if view_class is None:
        raise ContractValidationError(
            "Every /api/v1 route must expose discoverable DRF HTTP methods "
            "for contract validation."
        )

    initkwargs = getattr(callback, "initkwargs", None)
    configured_methods = getattr(view_class, "http_method_names", ())
    if isinstance(initkwargs, dict) and "http_method_names" in initkwargs:
        configured_methods = initkwargs["http_method_names"]

    allowed_methods = {
        method.lower()
        for method in configured_methods
        if isinstance(method, str)
    }

    methods = {
        method.upper()
        for method in HTTP_METHODS
        if (
            method in allowed_methods
            and callable(getattr(view_class, method, None))
            and not (
                method == "options"
                and getattr(view_class, method, None) is APIView.options
            )
        )
    }

    actions = getattr(callback, "actions", None)
    if isinstance(actions, dict):
        methods.update(
            method.upper()
            for method in actions
            if (
                isinstance(method, str)
                and method.lower() in HTTP_METHODS
                and method.lower() in allowed_methods
            )
        )

    return methods


def collect_implemented_operations(
    patterns: Iterable[URLPattern | URLResolver] | None = None,
) -> set[Operation]:
    resolved_patterns = patterns if patterns is not None else get_resolver().url_patterns
    operations: set[Operation] = set()
    equivalent_matchers: set[
        tuple[str, tuple[tuple[int, type[Any]], ...]]
    ] = set()

    def visit(
        entries: Iterable[URLPattern | URLResolver],
        prefix: str = "",
        matcher_prefix: str = "",
        converter_prefix: tuple[tuple[int, type[Any]], ...] = (),
        group_offset: int = 0,
    ) -> None:
        for entry in entries:
            route_segment = str(entry.pattern).removeprefix("^").removesuffix("$")
            route = prefix + route_segment
            pattern_regex, converter_bindings, group_count = (
                _pattern_match_signature(entry.pattern)
            )
            matcher = (
                matcher_prefix + pattern_regex,
                converter_prefix
                + tuple(
                    (group_offset + position, converter_type)
                    for position, converter_type in converter_bindings
                ),
            )
            if isinstance(entry, URLResolver):
                visit(
                    entry.url_patterns,
                    route,
                    *matcher,
                    group_offset + group_count,
                )
                continue

            normalized_path = _normalize_api_route(route)
            if normalized_path is None:
                continue

            # First-match deduplication is intentionally limited to equivalent
            # compiled matchers and custom-converter semantics; arbitrary containment
            # between distinct regexes or converters is out of scope.
            if matcher in equivalent_matchers:
                continue
            equivalent_matchers.add(matcher)

            for method in _callback_methods(entry.callback):
                operations.add(Operation(method, normalized_path))

    visit(resolved_patterns)
    return operations


def _canonical_operation(operation: Operation) -> Operation:
    return Operation(
        operation.method,
        _PATH_PLACEHOLDER_PATTERN.sub("{}", operation.path),
    )


def validate_implemented_operations(
    contract_operations: Mapping[Operation, str],
    implemented_operations: Iterable[Operation],
) -> int:
    implemented = set(implemented_operations)
    canonical_contract = {_canonical_operation(operation) for operation in contract_operations}
    unexpected = sorted(
        operation
        for operation in implemented
        if _canonical_operation(operation) not in canonical_contract
    )
    if unexpected:
        details = ", ".join(f"{operation.method} {operation.path}" for operation in unexpected)
        raise ContractValidationError(
            "Backend implementation drifted from the pinned Documentation OpenAPI contract: "
            f"{details}."
        )
    return len(implemented)


def check_current_implementation() -> tuple[int, int, str]:
    lock = load_contract_lock()
    document = fetch_pinned_openapi(lock)
    if not contract_declares_api_v1(document):
        raise ContractValidationError("The pinned contract no longer declares /api/v1.")

    contract_operations = parse_openapi_operations(document)
    implemented_operations = collect_implemented_operations()
    implemented_count = validate_implemented_operations(
        contract_operations,
        implemented_operations,
    )
    return implemented_count, len(contract_operations), lock.revision

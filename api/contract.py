from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, cast
from urllib.request import urlopen

from django.urls import URLPattern, URLResolver, get_resolver

API_PREFIX = "api/v1/"
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK_PATH = ROOT / "api" / "openapi-contract.lock.toml"

_PATH_PATTERN = re.compile(r"^  ['\"]?(?P<path>/[^'\"]+)['\"]?:\s*$")
_METHOD_PATTERN = re.compile(r"^    (?P<method>get|post|put|patch|delete):\s*$")
_OPERATION_ID_PATTERN = re.compile(r"^      operationId:\s*(?P<operation_id>\S+)\s*$")
_DJANGO_CONVERTER_PATTERN = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


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

    if not _REPOSITORY_PATTERN.fullmatch(lock.repository):
        raise ContractValidationError("Contract repository must use owner/name form.")
    if not _SHA_PATTERN.fullmatch(lock.revision):
        raise ContractValidationError("Contract revision must be a full 40-character commit SHA.")
    if not _SHA_PATTERN.fullmatch(lock.git_blob_sha):
        raise ContractValidationError("Contract blob SHA must be a full 40-character Git SHA.")
    if lock.path.startswith("/") or ".." in Path(lock.path).parts:
        raise ContractValidationError("Contract path must be a repository-relative safe path.")

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


def parse_openapi_operations(document: str) -> dict[Operation, str]:
    in_paths = False
    current_path: str | None = None
    current_operation: Operation | None = None
    operation_blocks = 0
    operations: dict[Operation, str] = {}

    for line in document.splitlines():
        if line == "paths:":
            in_paths = True
            current_path = None
            current_operation = None
            continue

        if not in_paths:
            continue

        if line and not line.startswith(" "):
            break

        path_match = _PATH_PATTERN.match(line)
        if path_match:
            current_path = path_match.group("path")
            current_operation = None
            continue

        method_match = _METHOD_PATTERN.match(line)
        if method_match and current_path is not None:
            current_operation = Operation(method_match.group("method").upper(), current_path)
            operation_blocks += 1
            continue

        operation_id_match = _OPERATION_ID_PATTERN.match(line)
        if operation_id_match and current_operation is not None:
            if current_operation in operations:
                raise ContractValidationError(
                    f"Duplicate contract operation: {current_operation.method} "
                    f"{current_operation.path}."
                )
            operation_id = operation_id_match.group("operation_id").strip("'\"")
            operations[current_operation] = operation_id
            current_operation = None

    if not in_paths or not operations:
        raise ContractValidationError("The pinned OpenAPI document contains no parsed operations.")
    if operation_blocks != len(operations):
        raise ContractValidationError(
            "Every OpenAPI operation must declare an operationId for drift validation."
        )

    return operations


def _normalize_api_route(route: str) -> str | None:
    if not route.startswith(API_PREFIX):
        return None

    relative_route = route[len(API_PREFIX) :].strip("/")
    normalized = _DJANGO_CONVERTER_PATTERN.sub(r"{\1}", relative_route)
    return "/" + normalized if normalized else "/"


def _callback_methods(callback: Any) -> set[str]:
    actions = getattr(callback, "actions", None)
    if isinstance(actions, dict):
        return {
            method.upper()
            for method in actions
            if isinstance(method, str) and method.lower() in HTTP_METHODS
        }

    view_class = getattr(callback, "cls", None)
    if view_class is None:
        return set()

    return {
        method.upper()
        for method in HTTP_METHODS
        if callable(getattr(view_class, method, None))
    }


def collect_implemented_operations(
    patterns: Iterable[URLPattern | URLResolver] | None = None,
) -> set[Operation]:
    resolved_patterns = patterns if patterns is not None else get_resolver().url_patterns
    operations: set[Operation] = set()

    def visit(
        entries: Iterable[URLPattern | URLResolver],
        prefix: str = "",
    ) -> None:
        for entry in entries:
            route = prefix + str(entry.pattern)
            if isinstance(entry, URLResolver):
                visit(entry.url_patterns, route)
                continue

            normalized_path = _normalize_api_route(route)
            if normalized_path is None:
                continue

            for method in _callback_methods(entry.callback):
                operations.add(Operation(method, normalized_path))

    visit(resolved_patterns)
    return operations


def validate_implemented_operations(
    contract_operations: Mapping[Operation, str],
    implemented_operations: Iterable[Operation],
) -> int:
    implemented = set(implemented_operations)
    unexpected = sorted(implemented - set(contract_operations))
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
    if not re.search(r"(?m)^  - url: /api/v1\s*$", document):
        raise ContractValidationError("The pinned contract no longer declares /api/v1.")

    contract_operations = parse_openapi_operations(document)
    implemented_operations = collect_implemented_operations()
    implemented_count = validate_implemented_operations(
        contract_operations,
        implemented_operations,
    )
    return implemented_count, len(contract_operations), lock.revision

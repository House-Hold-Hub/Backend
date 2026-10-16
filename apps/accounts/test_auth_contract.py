"""Responses of the authentication operations validated against the pinned Documentation contract.

Runs when ``HOUSEHOLDHUB_OPENAPI_SPEC`` points at the pinned ``api/openapi.yaml`` (as the real-contract
test in ``apps/api`` does). Checks the status is declared for the operation, the body matches the declared
schema (required, types, enums, nullability, ``additionalProperties: false``) and declared headers are sent.
"""

import datetime
import os
import uuid
from collections.abc import Callable
from typing import Any

import pytest

from apps.accounts.test_auth_api import PASSWORD, Browser, account
from apps.api.contract import load_contract, load_pin

pytestmark = pytest.mark.skipif(
    not os.environ.get("HOUSEHOLDHUB_OPENAPI_SPEC"),
    reason="set HOUSEHOLDHUB_OPENAPI_SPEC to the pinned Documentation api/openapi.yaml",
)


@pytest.fixture(scope="module")
def spec():
    return load_contract(os.environ["HOUSEHOLDHUB_OPENAPI_SPEC"], load_pin())


def resolve(spec, node):
    while "$ref" in node:
        target = spec
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = target
    return node


def _email(value: str) -> None:
    local, at, domain = value.partition("@")
    assert local and at and "." in domain, value


FORMATS: dict[str, Callable[[str], object]] = {
    "uuid": uuid.UUID,
    "date-time": lambda value: datetime.datetime.fromisoformat(value.replace("Z", "+00:00")),
    "email": _email,
}
TYPES: dict[str, type] = {"string": str, "boolean": bool, "integer": int, "object": dict, "array": list}


def validate(spec, schema, value: Any, path="$"):
    schema = resolve(spec, schema)
    if value is None:
        assert schema.get("nullable"), f"{path} is null but not nullable"
        return
    expected = TYPES[schema["type"]]
    assert isinstance(value, expected) and not (expected is int and isinstance(value, bool)), f"{path}: {value!r}"
    if "enum" in schema:
        assert value in schema["enum"], f"{path}: {value!r} not in {schema['enum']}"
    if isinstance(value, str) and schema.get("format") in FORMATS:
        FORMATS[schema["format"]](value)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        missing = set(schema.get("required", [])) - set(value)
        assert not missing, f"{path} lacks {missing}"
        if schema.get("additionalProperties") is False:
            assert set(value) <= set(properties), f"{path} has undeclared {set(value) - set(properties)}"
        for name, item in value.items():
            if name in properties:
                validate(spec, properties[name], item, f"{path}.{name}")


def operation(spec, path, method):
    return spec["paths"][path][method]


def check(spec, response, path, method):
    op = operation(spec, path, method)
    declared = op["responses"].get(str(response.status_code))
    assert declared is not None, f"{method.upper()} {path} returned undeclared {response.status_code}"
    declared = resolve(spec, declared)
    content = declared.get("content", {}).get("application/json")
    if content:
        validate(spec, content["schema"], response.json())
    else:
        assert response.content == b""
    for header in declared.get("headers", {}):
        if header == "Set-Cookie":
            assert response.cookies, f"{path} {response.status_code} declares Set-Cookie"
        else:
            assert response.has_header(header), f"{path} {response.status_code} lacks {header}"
    if response.status_code == 429:
        assert response.has_header("Retry-After")


@pytest.mark.django_db
def test_every_auth_operation_conforms(spec, make_user):
    browser = Browser()
    check(spec, browser.client.get("/api/v1/auth/csrf"), "/auth/csrf", "get")
    check(spec, browser.get("me"), "/auth/me", "get")  # 401
    check(spec, browser.post("logout"), "/auth/logout", "post")  # 401
    check(spec, browser.post("signup", {"email": "x"}), "/auth/signup", "post")  # 400
    check(spec, browser.signup(), "/auth/signup", "post")  # 201
    check(spec, browser.get("me"), "/auth/me", "get")  # 200
    check(spec, browser.post("logout"), "/auth/logout", "post")  # 204

    account(make_user)
    check(spec, browser.signup(email="member@example.com"), "/auth/signup", "post")  # 409
    check(spec, browser.post("login", {"email": "x"}), "/auth/login", "post")  # 400
    check(spec, browser.login("member@example.com", "a wrong passphrase!!"), "/auth/login", "post")  # 401
    check(spec, browser.login("member@example.com"), "/auth/login", "post")  # 200
    for _ in range(5):
        browser.login("member@example.com", "a wrong passphrase!!")
    check(spec, browser.login("member@example.com", PASSWORD), "/auth/login", "post")  # 429
    for i in range(10):
        browser.signup(email=f"flood{i}@example.com")
    check(spec, browser.signup(email="flood99@example.com"), "/auth/signup", "post")  # 429


def test_contract_bounds_match_the_password_validators(spec, settings):
    signup = resolve(spec, spec["components"]["schemas"]["SignupRequest"])["properties"]["password"]
    options = {v["NAME"].rsplit(".", 1)[1]: v.get("OPTIONS", {}) for v in settings.AUTH_PASSWORD_VALIDATORS}
    assert signup["minLength"] == options["MinimumLengthValidator"]["min_length"]
    assert signup["maxLength"] == options["MaximumLengthValidator"]["max_length"]
    login = resolve(spec, spec["components"]["schemas"]["LoginRequest"])["properties"]["password"]
    assert "minLength" not in login and "maxLength" not in login

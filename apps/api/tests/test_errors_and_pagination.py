import pytest
from django.test import Client, override_settings


def test_unknown_api_route_returns_json_error_response(client):
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"code": "NOT_FOUND", "message": "Not found."}


def test_real_urlconf_serves_json_404_for_api_paths_only(client):
    with override_settings(ROOT_URLCONF="config.urls"):
        api = Client().get("/api/v1/nothing-here")
        other = Client().get("/nothing-here")
    assert api.status_code == 404 and api.json()["code"] == "NOT_FOUND"
    assert other.status_code == 404 and "json" not in other["Content-Type"]


def test_unauthenticated_request_is_401_not_403(client):
    response = client.get("/api/v1/protected")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_ERROR"
    assert "WWW-Authenticate" not in response


def test_authenticated_request_is_served(client, user):
    client.force_authenticate(user)
    assert client.get("/api/v1/protected").json() == {"ok": True}


def test_validation_errors_are_400_with_flat_string_lists(client):
    response = client.get("/api/v1/boom?kind=validation")
    assert response.status_code == 400
    assert response.json() == {
        "code": "VALIDATION_ERROR",
        "message": "Validation failed.",
        "fields": {"name": ["required"], "items.0.qty": ["bad"], "x": ["plain"]},
    }


def test_validation_error_without_field_uses_non_field_errors(client):
    assert client.get("/api/v1/boom?kind=non_field").json()["fields"] == {"non_field_errors": ["generic"]}


def test_parse_error_is_400(client):
    response = client.get("/api/v1/boom?kind=parse")
    assert (response.status_code, response.json()["code"]) == (400, "VALIDATION_ERROR")


def test_django_404_becomes_not_found_response(client):
    response = client.get("/api/v1/boom?kind=http404")
    assert (response.status_code, response.json()["code"]) == (404, "NOT_FOUND")


def test_throttled_is_429_with_retry_after(client):
    response = client.get("/api/v1/boom?kind=throttled")
    assert response.status_code == 429
    assert response.json()["code"] == "RATE_LIMITED"
    assert response["Retry-After"] == "7"


def test_other_client_errors_keep_status_and_use_a_contract_code(client):
    response = client.get("/api/v1/boom?kind=method")
    assert response.status_code == 405
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_unexpected_exception_is_a_json_500(api_urls):
    from rest_framework.test import APIClient

    response = APIClient(raise_request_exception=False).get("/api/v1/boom?kind=unexpected")
    assert response.status_code == 500
    assert response.json() == {"code": "INTERNAL_ERROR", "message": "Internal server error."}


def test_422_is_never_produced_for_invalid_input(client):
    assert client.get("/api/v1/numbers?limit=0").status_code == 400


def test_pagination_defaults_and_envelope(client):
    body = client.get("/api/v1/numbers").json()
    assert body["meta"] == {"page": 1, "limit": 20, "total": 250}
    assert body["data"] == list(range(20))


def test_pagination_page_and_limit(client):
    body = client.get("/api/v1/numbers?page=3&limit=100").json()
    assert body["meta"] == {"page": 3, "limit": 100, "total": 250}
    assert body["data"] == list(range(200, 250))


def test_page_past_the_end_is_an_empty_page_not_404(client):
    response = client.get("/api/v1/numbers?page=99")
    assert response.status_code == 200
    assert response.json()["data"] == []
    assert response.json()["meta"]["total"] == 250


@pytest.mark.parametrize(
    "query, field",
    [("page=0", "page"), ("page=-1", "page"), ("page=abc", "page"), ("limit=0", "limit"), ("limit=101", "limit"), ("limit=x", "limit")],
)
def test_invalid_pagination_parameters_are_400(client, query, field):
    response = client.get(f"/api/v1/numbers?{query}")
    assert response.status_code == 400
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert field in response.json()["fields"]

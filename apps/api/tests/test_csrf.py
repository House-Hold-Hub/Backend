import uuid

from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory

from . import support


def _token(client):
    return client.get("/api/v1/csrf").json()["csrf_token"]


def test_public_unsafe_request_without_csrf_token_is_rejected(csrf_client):
    response = csrf_client.post("/api/v1/public", {}, format="json")
    assert response.status_code == 403
    assert response.json()["code"] == "AUTHORIZATION_ERROR"


def test_public_unsafe_request_with_valid_csrf_token_passes(csrf_client):
    token = _token(csrf_client)
    response = csrf_client.post("/api/v1/public", {}, format="json", HTTP_X_CSRFTOKEN=token)
    assert response.status_code == 200


def test_public_unsafe_request_with_wrong_csrf_token_is_rejected(csrf_client):
    _token(csrf_client)
    response = csrf_client.post("/api/v1/public", {}, format="json", HTTP_X_CSRFTOKEN="wrong")
    assert response.status_code == 403


def test_safe_requests_need_no_csrf_token(csrf_client):
    assert csrf_client.get("/api/v1/public").status_code == 200


def test_authenticated_unsafe_request_requires_csrf_token(csrf_client, user):
    csrf_client.force_authenticate(user)
    assert csrf_client.post("/api/v1/protected", {}, format="json").status_code == 403
    token = _token(csrf_client)
    assert csrf_client.post("/api/v1/protected", {}, format="json", HTTP_X_CSRFTOKEN=token).status_code == 200


def test_unauthenticated_call_to_protected_operation_is_401_even_without_csrf_token(csrf_client):
    response = csrf_client.post("/api/v1/protected", {}, format="json")
    assert response.status_code == 401


def test_session_authenticated_user_is_csrf_checked_by_session_authentication():
    request = APIRequestFactory(enforce_csrf_checks=True).post("/api/v1/protected", {}, format="json")
    request.user = get_user_model()(id=uuid.uuid4(), username="s")  # what AuthenticationMiddleware provides
    response = support.ProtectedPost.as_view()(request)
    assert response.status_code == 403

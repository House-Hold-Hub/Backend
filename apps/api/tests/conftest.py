import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from . import support


@pytest.fixture(autouse=True)
def isolated_support_state():
    support.MEMBERSHIPS.clear()
    support.OBJECTS.clear()
    support.CALLS.clear()


@pytest.fixture
def api_urls():
    with override_settings(ROOT_URLCONF="apps.api.tests.support"):
        yield


@pytest.fixture
def user(make_user):
    """A verified, active account: the only kind that may use protected operations."""
    return make_user("member@example.com")


@pytest.fixture
def client(api_urls):
    return APIClient()


@pytest.fixture
def csrf_client(api_urls):
    return APIClient(enforce_csrf_checks=True)

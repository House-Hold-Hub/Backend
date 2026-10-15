import uuid

import pytest
from django.contrib.auth import get_user_model
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
def user():
    return get_user_model()(id=uuid.uuid4(), username="member")


@pytest.fixture
def client(api_urls):
    return APIClient()


@pytest.fixture
def csrf_client(api_urls):
    return APIClient(enforce_csrf_checks=True)

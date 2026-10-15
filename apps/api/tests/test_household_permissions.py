"""Membership is checked before any action/object authorization; every miss fails closed."""

import uuid

import pytest
from django.core.exceptions import ImproperlyConfigured
from rest_framework.test import APIClient

from . import support

HOUSEHOLD = uuid.uuid4()
OTHER_HOUSEHOLD = uuid.uuid4()
ITEM = uuid.uuid4()


def items_url(household=HOUSEHOLD):
    return f"/api/v1/households/{household}/items"


def item_url(household=HOUSEHOLD, item=ITEM):
    return f"/api/v1/households/{household}/items/{item}"


@pytest.fixture
def member(client, user):
    support.MEMBERSHIPS[(user.pk, str(HOUSEHOLD))] = "member"
    client.force_authenticate(user)
    return user


def test_unauthenticated_gets_401_and_membership_is_never_consulted(client):
    response = client.get(items_url())
    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_ERROR"
    assert support.CALLS == []


def test_active_member_is_authorized(client, member):
    assert client.get(items_url()).status_code == 200
    assert support.CALLS == ["resolve_membership", "action"]


def test_non_member_gets_404_and_no_authorization_hook_runs(client, user):
    client.force_authenticate(user)
    response = client.get(items_url())
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"
    assert support.CALLS == ["resolve_membership"]


def test_member_of_another_household_gets_404(client, member):
    assert client.get(items_url(OTHER_HOUSEHOLD)).status_code == 404


def test_unknown_household_and_foreign_household_are_indistinguishable(client, member):
    assert client.get(items_url(uuid.uuid4())).json() == client.get(items_url(OTHER_HOUSEHOLD)).json()


def test_denied_action_inside_household_is_403(client, member):
    response = client.delete(items_url())
    assert response.status_code == 403
    assert response.json()["code"] == "AUTHORIZATION_ERROR"
    assert support.CALLS == ["resolve_membership", "action"]


def test_object_permission_is_not_reached_for_a_non_member_even_if_it_would_grant(client, user):
    # The user created the object, so the object rule would allow DELETE, but they are not a member.
    support.OBJECTS[str(ITEM)] = support.Obj(HOUSEHOLD, user.pk)
    client.force_authenticate(user)
    response = client.get(item_url())
    assert response.status_code == 404
    assert "object" not in support.CALLS
    assert "action" not in support.CALLS


def test_member_reads_object_of_their_household(client, member):
    support.OBJECTS[str(ITEM)] = support.Obj(HOUSEHOLD, uuid.uuid4())
    assert client.get(item_url()).status_code == 200
    assert support.CALLS == ["resolve_membership", "action", "object"]


def test_membership_is_resolved_once_per_request_and_before_object_authorization(client, member):
    support.OBJECTS[str(ITEM)] = support.Obj(HOUSEHOLD, uuid.uuid4())
    client.get(item_url())
    assert support.CALLS.count("resolve_membership") == 1
    assert support.CALLS.index("resolve_membership") < support.CALLS.index("object")


def test_object_denied_inside_household_is_403(client, member):
    # POST passes the action rule; the object rule only lets the creator through.
    support.OBJECTS[str(ITEM)] = support.Obj(HOUSEHOLD, uuid.uuid4())
    response = client.post(item_url(), {}, format="json")
    assert response.status_code == 403
    assert response.json()["code"] == "AUTHORIZATION_ERROR"
    assert support.CALLS == ["resolve_membership", "action", "object"]


def test_object_allowed_for_creator_inside_household(client, member):
    support.OBJECTS[str(ITEM)] = support.Obj(HOUSEHOLD, member.pk)
    assert client.post(item_url(), {}, format="json").status_code == 200


def test_object_from_another_household_is_404_not_403(client, member):
    # Even though the member created it (object rule would allow), it is outside the URL's household.
    support.OBJECTS[str(ITEM)] = support.Obj(OTHER_HOUSEHOLD, member.pk)
    response = client.get(item_url())
    assert response.status_code == 404
    assert "object" not in support.CALLS


def test_object_without_household_reference_fails_closed(client, member):
    support.OBJECTS[str(ITEM)] = support.Obj(None, member.pk)
    assert client.get(item_url()).status_code == 404


def test_subclasses_must_grant_explicitly(client, member):
    response = client.get(f"/api/v1/households/{HOUSEHOLD}/default-deny")
    assert response.status_code == 403


def test_unwired_permission_never_grants(api_urls, user):
    client = APIClient(raise_request_exception=True)
    client.force_authenticate(user)
    with pytest.raises(NotImplementedError):
        client.get(f"/api/v1/households/{HOUSEHOLD}/unwired")


def test_route_without_household_kwarg_is_a_configuration_error_not_a_grant(api_urls, user):
    client = APIClient(raise_request_exception=True)
    client.force_authenticate(user)
    with pytest.raises(ImproperlyConfigured):
        client.get("/api/v1/no-household")


def test_removed_membership_is_denied_on_the_next_request(client, member):
    assert client.get(items_url()).status_code == 200
    del support.MEMBERSHIPS[(member.pk, str(HOUSEHOLD))]
    assert client.get(items_url()).status_code == 404

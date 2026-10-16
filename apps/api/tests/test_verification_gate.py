"""The central verification gate: unverified and disabled accounts never reach protected operations."""

import uuid

import pytest
from allauth.account.models import EmailAddress

from . import support

HOUSEHOLD = uuid.uuid4()
PROTECTED = "/api/v1/protected"
LIFECYCLE = "/api/v1/lifecycle"
PUBLIC = "/api/v1/public"
HOUSEHOLD_ITEMS = f"/api/v1/households/{HOUSEHOLD}/items"
HOUSEHOLD_DEFAULT_DENY = f"/api/v1/households/{HOUSEHOLD}/default-deny"
HOUSEHOLD_UNWIRED = f"/api/v1/households/{HOUSEHOLD}/unwired"

pytestmark = pytest.mark.django_db


def _forbidden(response):
    assert response.status_code == 403
    assert response.json() == {"code": "AUTHORIZATION_ERROR", "message": "You do not have permission to perform this action."}


def _unauthenticated(response):
    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_ERROR"


# ---- anonymous ------------------------------------------------------------------------------


@pytest.mark.parametrize("url", [PROTECTED, LIFECYCLE, HOUSEHOLD_ITEMS, HOUSEHOLD_DEFAULT_DENY])
def test_anonymous_is_401_everywhere_protected(client, url):
    _unauthenticated(client.get(url))


def test_anonymous_can_use_public_operations(client):
    assert client.get(PUBLIC).status_code == 200


# ---- verified -------------------------------------------------------------------------------


def test_verified_user_reaches_protected_and_lifecycle_operations(client, user):
    client.force_authenticate(user)
    assert client.get(PROTECTED).status_code == 200
    assert client.get(LIFECYCLE).status_code == 200


def test_verified_member_reaches_household_operations(client, user):
    support.MEMBERSHIPS[(user.pk, str(HOUSEHOLD))] = "member"
    client.force_authenticate(user)
    assert client.get(HOUSEHOLD_ITEMS).status_code == 200


# ---- unverified -----------------------------------------------------------------------------


@pytest.mark.parametrize("url", [PROTECTED, HOUSEHOLD_ITEMS, HOUSEHOLD_DEFAULT_DENY, HOUSEHOLD_UNWIRED])
def test_unverified_user_is_denied_every_protected_operation(client, make_user, url):
    client.force_authenticate(make_user("new@example.com", verified=False))
    _forbidden(client.get(url))


def test_unverified_write_is_denied(client, make_user):
    client.force_authenticate(make_user("new@example.com", verified=False))
    _forbidden(client.post(PROTECTED, {}, format="json"))


def test_unverified_user_reaches_only_the_verification_lifecycle(client, make_user):
    client.force_authenticate(make_user("new@example.com", verified=False))
    assert client.get(LIFECYCLE).status_code == 200
    assert client.post(LIFECYCLE, {}, format="json").status_code == 200


def test_unverified_user_can_still_use_public_operations(client, make_user):
    client.force_authenticate(make_user("new@example.com", verified=False))
    assert client.get(PUBLIC).status_code == 200


def test_gate_runs_before_membership_resolution_and_permission_rules(client, make_user):
    unverified = make_user("new@example.com", verified=False)
    support.MEMBERSHIPS[(unverified.pk, str(HOUSEHOLD))] = "owner"  # even a real member is denied
    client.force_authenticate(unverified)
    _forbidden(client.get(HOUSEHOLD_ITEMS))
    assert support.CALLS == []


def test_unverified_gets_403_not_404_for_a_foreign_household(client, make_user):
    client.force_authenticate(make_user("new@example.com", verified=False))
    _forbidden(client.get(f"/api/v1/households/{uuid.uuid4()}/items"))


def test_account_without_any_verification_record_is_unverified(client, make_user):
    user = make_user("new@example.com")
    EmailAddress.objects.filter(user=user).delete()
    client.force_authenticate(user)
    _forbidden(client.get(PROTECTED))


def test_verified_secondary_address_does_not_verify_the_account(client, make_user):
    user = make_user("new@example.com", verified=False)
    EmailAddress.objects.create(user=user, email="other@example.com", verified=True)
    client.force_authenticate(user)
    _forbidden(client.get(PROTECTED))


def test_verification_of_another_user_does_not_verify_this_one(client, make_user):
    victim = make_user("victim@example.com", verified=False)
    make_user("attacker@example.com", verified=True)
    client.force_authenticate(victim)
    _forbidden(client.get(PROTECTED))


def test_changing_the_email_without_verifying_it_revokes_access(client, user):
    user.email = "changed@example.com"
    user.save()
    client.force_authenticate(user)
    _forbidden(client.get(PROTECTED))


def test_staff_and_superusers_get_no_exemption(client, make_user):
    client.force_authenticate(make_user("root@example.com", verified=False, is_staff=True, is_superuser=True))
    _forbidden(client.get(PROTECTED))


def test_verification_is_read_on_every_request(client, make_user):
    user = make_user("new@example.com", verified=False)
    client.force_authenticate(user)
    _forbidden(client.get(PROTECTED))
    EmailAddress.objects.filter(user=user).update(verified=True)
    assert client.get(PROTECTED).status_code == 200
    EmailAddress.objects.filter(user=user).update(verified=False)
    _forbidden(client.get(PROTECTED))


# ---- disabled -------------------------------------------------------------------------------


def test_disabled_user_with_a_live_session_is_unauthenticated_on_the_next_request(client, make_user):
    user = make_user("member@example.com")
    client.force_login(user)
    assert client.get(PROTECTED).status_code == 200
    user.is_active = False
    user.save()
    _unauthenticated(client.get(PROTECTED))
    _unauthenticated(client.get(LIFECYCLE))


def test_disabled_user_is_denied_even_if_authentication_were_bypassed(client, make_user):
    user = make_user("member@example.com", is_active=False)
    client.force_authenticate(user)
    _forbidden(client.get(PROTECTED))
    _forbidden(client.get(HOUSEHOLD_ITEMS))


def test_disabled_unverified_user_is_denied(client, make_user):
    client.force_authenticate(make_user("member@example.com", verified=False, is_active=False))
    _forbidden(client.get(PROTECTED))


# ---- fail closed ----------------------------------------------------------------------------


def test_user_object_without_verification_state_is_denied(client):
    class Opaque:
        is_authenticated = True
        is_active = True
        pk = uuid.uuid4()

    client.force_authenticate(Opaque())
    _forbidden(client.get(PROTECTED))


def test_views_deny_unverified_by_default():
    from apps.api.views import ApiView, ContractViewMixin

    assert ContractViewMixin.allow_unverified is False
    assert ApiView.allow_unverified is False

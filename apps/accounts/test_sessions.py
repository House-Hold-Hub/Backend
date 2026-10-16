"""Session registry, rotation and the ADR-011 revocation matrix, through real requests and allauth flows.

Each ``Client`` is one browser. The views below are test-only stand-ins for the authentication
endpoints of Backend#8, #9, #35 and #36: they call the same django-allauth flows those endpoints
will call, so the receivers in ``signals.py`` run exactly as they will in production.
"""

import datetime
import json
import os
import subprocess
import sys
import uuid
from unittest import mock

import pytest
from allauth.account.authentication import AUTHENTICATION_METHODS_SESSION_KEY
from allauth.account.internal.flows import logout as logout_flow
from allauth.account.internal.flows import manage_email, password_change, password_reset
from allauth.account.internal.flows.login import perform_login, record_authentication
from allauth.account.models import EmailAddress, Login
from allauth.socialaccount import signals as social_signals
from allauth.socialaccount.models import SocialAccount, SocialLogin
from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, authenticate, get_user_model
from django.contrib.auth import login as django_login
from django.core.management import call_command
from django.db import connection
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.test import Client, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import path
from django.utils import timezone

from apps.accounts.models import Session
from apps.accounts.sessions import (
    INVITATION_INTENT_SESSION_KEY,
    ROTATION_PRESERVED_KEYS,
    InvitationIntent,
    SessionStore,
    clear_invitation_intent,
    get_invitation_intent,
    revoke_all_sessions,
    revoke_other_sessions,
    rotate_and_revoke_others,
    set_invitation_intent,
)

User = get_user_model()
PASSWORD = "correct-Horse-battery-9"
NEW_PASSWORD = "another-Staple-battery-7"
INVITATION_ID = uuid.UUID("0b9cfa3e-8f4e-4a43-9d7f-4b3c8e1a2f55")

pytestmark = [pytest.mark.django_db, pytest.mark.urls(__name__)]


# ---- test-only views (the flows the authentication endpoints will call) ----------------------------


def whoami(request):
    intent = get_invitation_intent(request.session)
    return JsonResponse(
        {
            "user": str(request.user.pk) if request.user.is_authenticated else None,
            "intent": [str(intent.invitation_id), intent.generation] if intent else None,
            "keys": sorted(request.session.keys()),
        }
    )


def exchange(request):
    """What a successful ADR-013 exchange leaves behind, plus unrelated pre-login state."""
    set_invitation_intent(request.session, INVITATION_ID, 3)
    request.session["scratch"] = "unapproved state"
    return JsonResponse({})


def password_login(request):
    user = authenticate(request, username=request.POST["email"], password=request.POST["password"])
    assert user is not None
    record_authentication(request, user, method="password", email=user.email)  # as allauth's login form does
    perform_login(request, Login(user=user, email=user.email))
    return JsonResponse({})


def plain_login(request):
    django_login(request, User.objects.get(email=request.POST["email"]), backend=settings.AUTHENTICATION_BACKENDS[0])
    return JsonResponse({})


def logout_view(request):
    logout_flow.logout(request)
    return JsonResponse({})


def change_password_view(request):
    password_change.change_password(request.user, NEW_PASSWORD)
    password_change.finalize_password_change(request, request.user)
    return JsonResponse({})


def set_password_view(request):
    password_change.change_password(request.user, NEW_PASSWORD)
    password_change.finalize_password_set(request, request.user)
    return JsonResponse({})


def reset_password_view(request, user_id):
    user = User.objects.get(pk=user_id)
    password_reset.reset_password(user, NEW_PASSWORD)
    password_reset.finalize_password_reset(request, user)
    return JsonResponse({})


def make_primary_view(request):
    address = EmailAddress.objects.get(user=request.user, email=request.POST["email"])
    assert manage_email.mark_as_primary(request, address)
    return JsonResponse({})


def email_changed_elsewhere_view(request, user_id):
    """An email change confirmed from a browser that holds no session of the account."""
    user = User.objects.get(pk=user_id)
    old = EmailAddress.objects.get(user=user, primary=True)
    new = EmailAddress.objects.get(user=user, primary=False)
    new.set_as_primary()
    manage_email.emit_email_changed(request, old, new)
    return JsonResponse({})


def link_view(request):
    account = SocialAccount.objects.create(user=request.user, provider="google", uid="google-uid-1")
    social_signals.social_account_added.send(
        sender=SocialLogin, request=request, sociallogin=SocialLogin(user=request.user, account=account)
    )
    return JsonResponse({})


def unlink_view(request):
    account = SocialAccount.objects.get(user=request.user)
    account.delete()
    social_signals.social_account_removed.send(sender=SocialAccount, request=request, socialaccount=account)
    return JsonResponse({})


def csrf_view(request):
    get_token(request)
    request.session["touched"] = True
    return JsonResponse({})


urlpatterns = [
    path("whoami", whoami),
    path("exchange", exchange),
    path("login", password_login),
    path("plain-login", plain_login),
    path("logout", logout_view),
    path("password/change", change_password_view),
    path("password/set", set_password_view),
    path("password/reset/<uuid:user_id>", reset_password_view),
    path("email/primary", make_primary_view),
    path("email/changed-elsewhere/<uuid:user_id>", email_changed_elsewhere_view),
    path("social/link", link_view),
    path("social/unlink", unlink_view),
    path("csrf", csrf_view),
]


# ---- helpers ---------------------------------------------------------------------------------------


@pytest.fixture
def user(make_user):
    account = make_user("alice@example.com", name="Alice")
    account.set_password(PASSWORD)
    account.save()
    return account


def signed_in(user):
    browser = Client()
    browser.force_login(user)
    return browser


def who(browser):
    return json.loads(browser.get("/whoami").content)


def key(browser):
    return browser.cookies[settings.SESSION_COOKIE_NAME].value


def with_cookie(session_key):
    browser = Client()
    browser.cookies[settings.SESSION_COOKIE_NAME] = session_key
    return browser


def owned(user):
    return set(Session.objects.filter(user=user).values_list("session_key", flat=True))


# ---- the registry ----------------------------------------------------------------------------------


def test_the_session_engine_is_the_registry_backed_database_store():
    assert settings.SESSION_ENGINE == "apps.accounts.sessions"
    assert SessionStore.get_model_class() is Session
    assert Session.get_session_store_class() is SessionStore


def test_login_records_the_owner_and_anonymous_sessions_have_none(user):
    anonymous = Client()
    anonymous.get("/exchange")
    browser = signed_in(user)
    assert owned(user) == {key(browser)}
    assert Session.objects.get(session_key=key(anonymous)).user_id is None


def test_the_owner_column_is_indexed():
    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(cursor, Session._meta.db_table)
    assert any(c["columns"] == ["user_id"] and c["index"] for c in constraints.values())


def test_revocation_deletes_by_owner_without_reading_or_decoding_payloads(user):
    browsers = [signed_in(user) for _ in range(3)]
    with (
        mock.patch.object(SessionStore, "decode", side_effect=AssertionError("payload decoded")),
        CaptureQueriesContext(connection) as queries,
    ):
        assert revoke_all_sessions(user) == 3
    assert not any("session_data" in q["sql"] for q in queries.captured_queries)
    assert owned(user) == set()
    assert all(who(b)["user"] is None for b in browsers)


def test_revocation_leaves_other_accounts_alone(user, make_user):
    other = signed_in(make_user("bob@example.com"))
    signed_in(user)
    revoke_all_sessions(user)
    assert who(other)["user"] is not None


def test_revoke_other_sessions_keeps_only_the_named_one(user):
    keep, drop = signed_in(user), signed_in(user)
    assert revoke_other_sessions(user, keep_session_key=key(keep)) == 1
    assert who(keep)["user"] == str(user.pk)
    assert who(drop)["user"] is None


def test_expired_sessions_are_removed_by_the_scheduled_cleanup_command(user):
    browser = signed_in(user)
    Session.objects.filter(session_key=key(browser)).update(expire_date=timezone.now() - datetime.timedelta(seconds=1))
    assert who(browser)["user"] is None  # Django never loads an expired row
    call_command("clearsessions")
    assert owned(user) == set()


def test_sessions_last_fourteen_days():
    assert settings.SESSION_COOKIE_AGE == 14 * 24 * 60 * 60


def test_a_payload_whose_user_id_is_malformed_is_stored_without_an_owner():
    store = SessionStore()
    store[SESSION_KEY] = "not-a-uuid"
    store.create()
    assert Session.objects.get(session_key=store.session_key).user_id is None


def test_a_payload_naming_a_deleted_user_never_gets_a_dangling_owner_or_survives_rotation():
    store = SessionStore()
    store[SESSION_KEY] = str(uuid.uuid4())  # e.g. the user was deleted while the request ran
    store.create()
    assert Session.objects.get(session_key=store.session_key).user_id is None
    store.cycle_key()
    assert dict(store.items()) == {}


def test_the_async_api_writes_the_owner_and_follows_the_rotation_rules(user):
    store = SessionStore()
    store.update({SESSION_KEY: str(user.pk), HASH_SESSION_KEY: user.get_session_auth_hash()})
    async_to_sync(store.asave)()
    first = store.session_key
    async_to_sync(store.acycle_key)()
    assert owned(user) == {store.session_key} and store.session_key != first


def test_deleting_a_user_deletes_its_sessions(user):
    signed_in(user)
    user.delete()
    assert not Session.objects.exists()


# ---- the seven revocation-matrix events ------------------------------------------------------------


def test_logout_revokes_only_the_current_session(user):
    current, other = signed_in(user), signed_in(user)
    old_key = key(current)
    current.post("/logout")
    assert who(current)["user"] is None
    assert who(with_cookie(old_key))["user"] is None
    assert old_key not in owned(user)
    assert who(other)["user"] == str(user.pk)


def test_password_reset_revokes_every_session(user):
    browsers = [signed_in(user) for _ in range(2)]
    anonymous = Client()
    assert anonymous.post(f"/password/reset/{user.pk}").status_code == 200
    assert owned(user) == set()
    assert all(who(b)["user"] is None for b in browsers)
    user.refresh_from_db()
    assert user.check_password(NEW_PASSWORD)


def test_password_reset_from_a_signed_in_browser_logs_that_browser_out_too(user):
    current, other = signed_in(user), signed_in(user)
    assert current.post(f"/password/reset/{user.pk}").status_code == 200  # not SessionInterrupted
    assert who(current)["user"] is None
    assert who(other)["user"] is None
    assert owned(user) == set()


@pytest.mark.parametrize("endpoint", ["/password/change", "/password/set"])
def test_authenticated_password_change_rotates_current_and_revokes_others(user, endpoint):
    current, other = signed_in(user), signed_in(user)
    old_key = key(current)
    assert current.post(endpoint).status_code == 200
    assert key(current) != old_key
    assert who(current)["user"] == str(user.pk)  # preserved, with the new authentication hash
    assert who(with_cookie(old_key))["user"] is None
    assert who(other)["user"] is None
    assert owned(user) == {key(current)}


def test_primary_email_change_rotates_current_and_revokes_others(user):
    EmailAddress.objects.create(user=user, email="alice@new.example.com", verified=True)
    current, other = signed_in(user), signed_in(user)
    old_key = key(current)
    assert current.post("/email/primary", {"email": "alice@new.example.com"}).status_code == 200
    user.refresh_from_db()
    assert user.email == "alice@new.example.com"
    assert key(current) != old_key
    assert who(current)["user"] == str(user.pk)
    assert who(with_cookie(old_key))["user"] is None
    assert who(other)["user"] is None
    assert owned(user) == {key(current)}


def test_email_change_from_a_browser_without_a_session_of_the_account_revokes_all(user):
    EmailAddress.objects.create(user=user, email="alice@new.example.com", verified=True)
    browsers = [signed_in(user) for _ in range(2)]
    Client().post(f"/email/changed-elsewhere/{user.pk}")
    assert owned(user) == set()
    assert all(who(b)["user"] is None for b in browsers)


@pytest.mark.parametrize("endpoint", ["/social/link", "/social/unlink"])
def test_oauth_link_and_unlink_rotate_current_and_revoke_others(user, endpoint):
    if endpoint == "/social/unlink":
        SocialAccount.objects.create(user=user, provider="google", uid="google-uid-1")
    current, other = signed_in(user), signed_in(user)
    old_key = key(current)
    assert current.post(endpoint).status_code == 200
    assert SocialAccount.objects.filter(user=user).exists() is (endpoint == "/social/link")
    assert key(current) != old_key
    assert who(current)["user"] == str(user.pk)
    assert who(with_cookie(old_key))["user"] is None
    assert who(other)["user"] is None
    assert owned(user) == {key(current)}


def test_disabling_an_account_revokes_every_session_immediately(user):
    browsers = [signed_in(user) for _ in range(2)]
    user.is_active = False
    user.save()
    assert owned(user) == set()
    assert all(who(b)["user"] is None for b in browsers)


def test_disabling_through_a_queryset_update_also_revokes(user):
    signed_in(user)
    User.objects.filter(pk=user.pk).update(is_active=False)
    assert owned(user) == set()


def test_saving_an_account_without_a_lifecycle_change_keeps_its_sessions(user):
    browser = signed_in(user)
    user.name = "Alice Liddell"
    user.save()
    assert who(browser)["user"] == str(user.pk)


def test_restoration_never_revives_an_old_session_and_needs_a_fresh_login(user):
    browser = signed_in(user)
    old_key = key(browser)
    user.is_active = False
    user.save()
    # A session row that exists for the disabled account anyway (written by code that bypassed
    # allauth's inactive-account check) must not become usable either.
    leftover = SessionStore()
    leftover.update({SESSION_KEY: str(user.pk), BACKEND_SESSION_KEY: settings.AUTHENTICATION_BACKENDS[0]})
    leftover[HASH_SESSION_KEY] = user.get_session_auth_hash()
    leftover.create()
    assert owned(user) == {leftover.session_key}

    user.is_active = True
    user.save()
    assert owned(user) == set()
    assert who(with_cookie(old_key))["user"] is None
    assert who(with_cookie(leftover.session_key))["user"] is None
    fresh = Client()
    fresh.post("/login", {"email": user.email, "password": PASSWORD})
    assert who(fresh)["user"] == str(user.pk)


def test_soft_deletion_can_revoke_through_the_shared_mechanism(user):
    # There is no soft-deletion model yet; whichever issue adds it calls revoke_all_sessions.
    signed_in(user)
    assert revoke_all_sessions(user) == 1
    assert owned(user) == set()


# ---- Django's authentication hash stays in force ---------------------------------------------------


def test_password_change_outside_the_flows_still_invalidates_sessions_through_the_hash(user):
    browser = signed_in(user)
    old_key = key(browser)
    user.set_password(NEW_PASSWORD)
    user.save()  # e.g. the admin's password form: no allauth signal, no registry call
    assert who(browser)["user"] is None
    assert old_key not in owned(user)  # get_user() flushed it


# ---- rotation and the invitation intent ------------------------------------------------------------


def test_login_rotates_the_session_key_and_keeps_the_invitation_intent(user):
    browser = Client()
    browser.get("/exchange")
    anonymous_key = key(browser)
    browser.post("/login", {"email": user.email, "password": PASSWORD})
    assert key(browser) != anonymous_key
    assert who(with_cookie(anonymous_key))["user"] is None
    state = who(browser)
    assert state["user"] == str(user.pk)
    assert state["intent"] == [str(INVITATION_ID), 3]
    assert owned(user) == {key(browser)}


def test_plain_django_login_records_the_owner_and_keeps_the_intent(user):
    browser = Client()
    browser.get("/exchange")
    browser.post("/plain-login", {"email": user.email})
    assert who(browser)["intent"] == [str(INVITATION_ID), 3]
    assert owned(user) == {key(browser)}


def test_login_as_another_account_does_not_inherit_the_previous_session(user, make_user):
    browser = Client()
    browser.get("/exchange")
    browser.post("/plain-login", {"email": make_user("bob@example.com").email})
    browser.post("/plain-login", {"email": user.email})  # Django flushes another account's session
    assert who(browser)["intent"] is None


@pytest.mark.parametrize("endpoint", ["/password/change", "/social/link"])
def test_identity_rotation_keeps_only_approved_state(user, endpoint):
    browser = Client()
    browser.get("/exchange")
    browser.post("/login", {"email": user.email, "password": PASSWORD})
    before = who(browser)["keys"]
    assert {"scratch", AUTHENTICATION_METHODS_SESSION_KEY} <= set(before)  # login keeps pre-login state
    browser.post(endpoint)
    state = who(browser)
    assert state["intent"] == [str(INVITATION_ID), 3]
    assert "scratch" not in state["keys"]
    assert set(state["keys"]) <= ROTATION_PRESERVED_KEYS
    assert AUTHENTICATION_METHODS_SESSION_KEY in state["keys"]  # allauth's reauthentication records


def test_identity_rotation_also_rotates_the_csrf_token(user):
    browser = signed_in(user)
    browser.get("/csrf")
    token = browser.cookies[settings.CSRF_COOKIE_NAME].value
    browser.post("/password/change")
    assert browser.cookies[settings.CSRF_COOKIE_NAME].value != token


def test_a_malformed_intent_is_dropped_at_rotation(user):
    browser = signed_in(user)
    store = SessionStore(key(browser))
    store[INVITATION_INTENT_SESSION_KEY] = {"invitation_id": str(INVITATION_ID), "token": "bearer-secret"}
    store.save()
    browser.post("/password/change")
    assert INVITATION_INTENT_SESSION_KEY not in who(browser)["keys"]


def test_the_intent_holds_only_an_identifier_and_a_generation():
    session = SessionStore()
    assert set_invitation_intent(session, INVITATION_ID, 0) == InvitationIntent(INVITATION_ID, 0)
    assert session[INVITATION_INTENT_SESSION_KEY] == {"invitation_id": str(INVITATION_ID), "generation": 0}
    for invitation_id, generation in [
        ("Zm9vYmFyLWJlYXJlci10b2tlbg", 1),  # a string, e.g. a bearer token, is refused
        (str(INVITATION_ID), 1),
        (INVITATION_ID, "1"),
        (INVITATION_ID, True),
        (INVITATION_ID, -1),
    ]:
        with pytest.raises(TypeError):
            set_invitation_intent(session, invitation_id, generation)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "stored",
    [
        None,
        "0b9cfa3e-8f4e-4a43-9d7f-4b3c8e1a2f55",
        {"invitation_id": "not-a-uuid", "generation": 1},
        {"invitation_id": str(INVITATION_ID), "generation": 1, "token": "secret"},
        {"invitation_id": str(INVITATION_ID), "generation": False},
    ],
)
def test_a_malformed_stored_intent_reads_as_none(stored):
    session = SessionStore()
    session[INVITATION_INTENT_SESSION_KEY] = stored
    assert get_invitation_intent(session) is None


def test_rotating_a_session_revoked_during_the_request_leaves_the_request_anonymous(user, rf):
    other = signed_in(user)
    request = rf.post("/")
    request.session = SessionStore(key(signed_in(user)))
    request.user = user
    assert SESSION_KEY in request.session  # loaded before the revocation below
    revoke_all_sessions(user)
    signed_in(user)  # a later, fresh login elsewhere
    assert rotate_and_revoke_others(request, user) == 1
    assert not request.user.is_authenticated
    assert SESSION_KEY not in request.session
    assert who(other)["user"] is None
    assert owned(user) == set()


def test_clearing_the_intent_removes_it():
    session = SessionStore()
    set_invitation_intent(session, INVITATION_ID, 1)
    clear_invitation_intent(session)
    clear_invitation_intent(session)
    assert get_invitation_intent(session) is None


def test_rotation_without_a_session_of_the_account_revokes_all(user, rf):
    signed_in(user)
    request = rf.post("/")
    request.session = SessionStore()
    assert rotate_and_revoke_others(request, user) == 1
    assert owned(user) == set()


# ---- cookies ---------------------------------------------------------------------------------------


@override_settings(SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True)
def test_session_cookie_is_httponly_secure_and_lax_and_csrf_cookie_is_readable(user):
    browser = Client()
    response = browser.post("/login", {"email": user.email, "password": PASSWORD})
    session_cookie = response.cookies[settings.SESSION_COOKIE_NAME]
    assert session_cookie["httponly"] is True
    assert session_cookie["secure"] is True
    assert session_cookie["samesite"] == "Lax"
    csrf_cookie = response.cookies[settings.CSRF_COOKIE_NAME]  # rotated by login()
    assert not csrf_cookie["httponly"]
    assert csrf_cookie["secure"] is True
    assert csrf_cookie["samesite"] == "Lax"


@pytest.mark.parametrize(("debug", "secure"), [("false", True), ("true", False)])
def test_cookies_are_secure_by_default_outside_local_development(debug, secure):
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SECURE_COOKIES"}
    env.update(DJANGO_DEBUG=debug, DJANGO_SETTINGS_MODULE="config.settings")
    script = (
        "import django; django.setup(); from django.conf import settings as s;"
        "print(s.SESSION_COOKIE_SECURE, s.CSRF_COOKIE_SECURE, s.SESSION_COOKIE_HTTPONLY, s.SESSION_COOKIE_SAMESITE)"
    )
    output = subprocess.run(
        [sys.executable, "-c", script], env=env, cwd=settings.BASE_DIR, capture_output=True, text=True, check=True
    ).stdout.split()
    assert output == [str(secure), str(secure), "True", "Lax"]

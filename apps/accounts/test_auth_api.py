"""getCsrfToken, signup, login, logout and getCurrentUser against the contract and ADR-011/013/015/016."""

import json
import logging
import threading
import uuid
from unittest import mock

import pytest
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.auth.password_validation import CommonPasswordValidator
from django.db import DatabaseError, connection
from django.test import Client, override_settings

from apps.accounts.models import EmailVerificationBearer, Session
from apps.accounts.sessions import INVITATION_INTENT_SESSION_KEY, get_invitation_intent, set_invitation_intent
from apps.accounts.verification import bearer_digest
from apps.email_delivery import adapter, service
from apps.email_delivery.adapter import ProviderNotConfigured, ProviderRejected, ProviderTimeout
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.testing import RecordingProvider
from apps.ratelimit.models import RateLimitBucket

User = get_user_model()
PASSWORD = "a long passphrase for tests"
NO_STORE = "private, no-store"
# A policy-length entry of Django's common-password list (read at runtime rather than written out here).
COMMON_LONG_PASSWORD = min(p for p in CommonPasswordValidator().passwords if len(p) >= 15 and p.isascii() and p.isalnum())


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    provider = RecordingProvider()
    monkeypatch.setattr(service, "get_provider", lambda: provider)
    return provider


@pytest.fixture
def browser():
    return Browser()


class Browser:
    """One browser: a cookie jar that bootstraps CSRF the way the SPA does and sends X-CSRFToken."""

    def __init__(self, remote_addr="203.0.113.10"):
        self.client = Client(enforce_csrf_checks=True, REMOTE_ADDR=remote_addr)

    def csrf(self):
        response = self.client.get("/api/v1/auth/csrf")
        assert response.status_code == 200
        return response.json()["csrf_token"]

    def token(self):
        cookie = self.client.cookies.get("csrftoken")
        return cookie.value if cookie else self.csrf()

    def post(self, path, body=None, *, csrf=True, raw=None):
        headers = {"HTTP_X_CSRFTOKEN": self.token()} if csrf else {}
        data = raw if raw is not None else json.dumps(body or {})
        return self.client.post(f"/api/v1/auth/{path}", data, content_type="application/json", **headers)

    def get(self, path):
        return self.client.get(f"/api/v1/auth/{path}")

    def signup(self, email="new.user@example.com", password=PASSWORD, name="New User", **kwargs):
        return self.post("signup", {"email": email, "password": password, "name": name}, **kwargs)

    def login(self, email, password=PASSWORD, **kwargs):
        return self.post("login", {"email": email, "password": password}, **kwargs)

    @property
    def session_key(self):
        cookie = self.client.cookies.get("sessionid")
        return cookie.value if cookie and cookie.value else None

    def session(self):
        return self.client.session


def account(make_user, email="member@example.com", *, verified=True, password=PASSWORD, **extra):
    user = make_user(email, verified=verified, **extra)
    user.set_password(password)
    user.save()
    return user


def put_intent(browser, invitation_id=None, generation=3, extra=None):
    """Simulate a prior invitation exchange: the intent (and any other state) in this browser's session."""
    browser.csrf()
    session = browser.client.session
    intent = set_invitation_intent(session, invitation_id or uuid.uuid4(), generation)
    for key, value in (extra or {}).items():
        session[key] = value
    session.save()
    browser.client.cookies["sessionid"] = session.session_key
    return intent


# ---- getCsrfToken ----------------------------------------------------------------------------------


@pytest.mark.django_db
def test_csrf_bootstrap_sets_readable_cookie_and_is_not_cacheable(browser):
    response = browser.client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    assert set(response.json()) == {"csrf_token"}
    cookie = response.cookies["csrftoken"]
    assert cookie.value and not cookie["httponly"] and cookie["samesite"] == "Lax"
    assert response["Cache-Control"] == NO_STORE


# ---- CSRF on unsafe operations, public ones included ------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("path", ["signup", "login"])
def test_public_unsafe_operations_require_csrf(browser, path):
    browser.csrf()  # the cookie alone is not enough: the header must echo it
    response = browser.post(path, {"email": "x@example.com", "password": PASSWORD, "name": "X"}, csrf=False)
    assert response.status_code == 403
    assert response.json()["code"] == "AUTHORIZATION_ERROR"
    assert not User.objects.exists()


@pytest.mark.django_db
def test_wrong_csrf_token_is_rejected(browser):
    browser.csrf()
    response = browser.client.post(
        "/api/v1/auth/signup",
        json.dumps({"email": "x@example.com", "password": PASSWORD, "name": "X"}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN="not-the-token",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_logout_requires_csrf(make_user, browser):
    account(make_user)
    browser.login("member@example.com")
    assert browser.post("logout", csrf=False).status_code == 403
    assert browser.get("me").status_code == 200


# ---- signup ------------------------------------------------------------------------------------------


@pytest.mark.django_db
def test_signup_creates_unverified_account_bearer_delivery_and_restricted_session(browser, provider):
    response = browser.signup(email="  New.User@Example.COM ", name="  New User ")
    assert response.status_code == 201
    assert response["Cache-Control"] == NO_STORE
    body = response.json()
    assert set(body) == {"user", "email_verification_required", "delivery"}
    assert body["email_verification_required"] is True
    assert body["user"]["email"] == "new.user@example.com"
    assert body["user"]["name"] == "New User"
    assert body["user"]["email_verified"] is False
    assert body["user"]["google_linked"] is False
    assert set(body["user"]) == {"id", "email", "name", "email_verified", "google_linked", "created_at"}
    assert set(body["delivery"]) == {"id", "purpose", "status", "created_at", "last_attempt_at", "provider_accepted_at"}
    assert body["delivery"]["purpose"] == "email_verification"

    user = User.objects.get()
    assert str(user.pk) == body["user"]["id"]
    assert user.check_password(PASSWORD)
    address = EmailAddress.objects.get(user=user)
    assert (address.email, address.primary, address.verified) == ("new.user@example.com", True, False)
    bearer = EmailVerificationBearer.objects.get(user=user)
    assert bearer.email == user.email and bearer.superseded_at is None and bearer.consumed_at is None
    assert (bearer.expires_at - bearer.created_at).total_seconds() == pytest.approx(24 * 3600, abs=5)
    delivery = EmailDelivery.objects.get()
    assert (str(delivery.pk), delivery.template, delivery.subject_id) == (body["delivery"]["id"], "email-verification", bearer.pk)

    # Restricted session: authenticated as the new account, current-user works, household data does not.
    assert browser.session()[SESSION_KEY] == str(user.pk)
    assert Session.objects.get(session_key=browser.session_key).user_id == user.pk
    cookie = response.cookies["sessionid"]
    assert cookie["httponly"] and cookie["samesite"] == "Lax"
    assert browser.get("me").json()["email_verified"] is False


@pytest.mark.django_db
def test_restricted_session_cannot_use_verified_only_operations(browser):
    browser.signup()
    with override_settings(ROOT_URLCONF="apps.accounts.auth_test_urls"):
        response = browser.client.get("/api/v1/test-protected")
    assert response.status_code == 403


@pytest.mark.django_db(transaction=True)
def test_signup_sends_verification_after_commit_with_bearer_only_in_fragment(browser, provider):
    response = browser.signup()
    assert response.status_code == 201
    delivery = response.json()["delivery"]
    assert delivery["status"] == "provider_accepted"
    assert delivery["provider_accepted_at"] is not None and delivery["last_attempt_at"] is not None

    [message] = provider.sent
    assert message.to == "new.user@example.com"
    link = next(word for word in message.text_body.split() if word.startswith("http"))
    base, _, fragment = link.partition("#")
    assert base == "http://testserver/verify-email"
    assert "?" not in base and fragment.startswith("verifier=")
    plaintext = fragment.removeprefix("verifier=")
    assert len(plaintext) >= 43  # 32 random bytes, URL-safe base64
    bearer = EmailVerificationBearer.objects.get()
    assert bearer.digest == bearer_digest(plaintext) != plaintext


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    "outcome, status",
    [(ProviderRejected("no"), "failed"), (ProviderNotConfigured("no"), "failed"), (ProviderTimeout("slow"), "unknown")],
)
def test_signup_survives_delivery_failure_with_recoverable_state(browser, provider, outcome, status):
    provider.outcome = outcome
    response = browser.signup()
    assert response.status_code == 201
    assert response.json()["delivery"]["status"] == status
    assert response.json()["delivery"]["provider_accepted_at"] is None
    user = User.objects.get()
    assert EmailDelivery.objects.get().status == status
    assert EmailVerificationBearer.objects.filter(user=user, superseded_at__isnull=True).count() == 1
    assert browser.get("me").status_code == 200


@pytest.mark.django_db(transaction=True)
def test_signup_with_the_default_unconfigured_provider_records_failure(browser, monkeypatch):
    monkeypatch.setattr(service, "get_provider", adapter.get_provider)  # the configured default (D02 open)
    response = browser.signup()
    assert response.status_code == 201
    assert response.json()["delivery"]["status"] == "failed"
    assert EmailDelivery.objects.get().error_class == "not_configured"


@pytest.mark.django_db
def test_signup_failure_in_the_transaction_leaves_nothing(browser, provider):
    with mock.patch("apps.accounts.views.issue_email_verification", side_effect=DatabaseError("boom")):
        with pytest.raises(DatabaseError):
            browser.signup()
    assert not User.objects.exists()
    assert not EmailAddress.objects.exists()
    assert not EmailDelivery.objects.exists()
    assert provider.sent == []


@pytest.mark.django_db
@pytest.mark.parametrize("existing", ["member@example.com", "MEMBER@example.com", " member@EXAMPLE.com "])
def test_signup_with_registered_email_is_409(make_user, browser, existing):
    account(make_user)
    response = browser.signup(email=existing)
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
    assert User.objects.count() == 1
    assert not EmailDelivery.objects.exists()
    assert browser.session_key is None or SESSION_KEY not in browser.session()


@pytest.mark.django_db
def test_signup_with_address_held_by_another_account_is_409(make_user, browser):
    other = account(make_user)
    EmailAddress.objects.create(user=other, email="secondary@example.com", primary=False, verified=True)
    assert browser.signup(email="secondary@example.com").status_code == 409


@pytest.mark.django_db(transaction=True)
def test_concurrent_signups_for_one_address_create_one_account():
    workers = 6
    barrier = threading.Barrier(workers)
    statuses = []
    browsers = [Browser(remote_addr=f"203.0.113.{i + 20}") for i in range(workers)]
    for b in browsers:
        b.csrf()

    def attempt(b):
        try:
            barrier.wait()
            statuses.append(b.signup(email="race@example.com").status_code)
        finally:
            connection.close()

    with override_settings(AUTH_RATE_LIMITS={**_limits(), "signup_email": (("email", 100, 3600),)}):
        threads = [threading.Thread(target=attempt, args=(b,)) for b in browsers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert sorted(statuses) == [201] + [409] * (workers - 1)
    assert User.objects.count() == 1
    assert EmailDelivery.objects.count() == 1


def _limits():
    from django.conf import settings

    return dict(settings.AUTH_RATE_LIMITS)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "body, field",
    [
        ({"email": "a@example.com", "password": "Zq9!xY7#wV5$uT", "name": "A"}, "password"),  # 14 < 15
        ({"email": "a@example.com", "password": "Zq9!" * 32 + "z", "name": "A"}, "password"),  # 129 > 128
        ({"email": "a@example.com", "password": COMMON_LONG_PASSWORD, "name": "A"}, "password"),
        ({"email": "someone.long.name@example.com", "password": "someone.long.name", "name": "A"}, "password"),
        ({"email": "not-an-email", "password": PASSWORD, "name": "A"}, "email"),
        ({"email": "a@example.com", "password": PASSWORD, "name": "   "}, "name"),
        ({"email": "a@example.com", "password": PASSWORD, "name": "n" * 151}, "name"),
        ({"email": "a@example.com", "password": PASSWORD}, "name"),
        ({"password": PASSWORD, "name": "A"}, "email"),
        ({"email": "a@example.com", "name": "A"}, "password"),
        ({"email": "a@example.com", "password": 123456789012345678, "name": "A"}, "password"),
        ({"email": "a@example.com", "password": PASSWORD, "name": "A", "is_staff": True}, "is_staff"),
    ],
)
def test_signup_validation_errors_are_400_never_422(browser, body, field):
    response = browser.post("signup", body)
    assert response.status_code == 400
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert field in response.json()["fields"]
    assert not User.objects.exists()


@pytest.mark.django_db
def test_signup_rejects_unpaired_surrogates_with_400(browser):
    raw = '{"email": "a@example.com", "password": "' + "x" * 15 + '\\ud800", "name": "A"}'
    response = browser.post("signup", raw=raw)
    assert response.status_code == 400
    assert "password" in response.json()["fields"]


@pytest.mark.django_db
def test_signup_rejects_malformed_json_with_400(browser):
    assert browser.post("signup", raw="{not json").status_code == 400


@pytest.mark.django_db
@pytest.mark.parametrize(
    "password",
    [
        "x7" * 7 + "\U0001f511",  # 15 code points (an astral character counts once)
        "9" * 15,  # all digits: no composition rule (ADR-016)
        "   spaces kept   ",  # surrounding spaces are part of the password
        "日本語のパスワードはとても長い",  # any Unicode
        "Zq9!" * 32,  # exactly 128
    ],
)
def test_signup_accepts_policy_conforming_passwords_as_entered(browser, password):
    response = browser.signup(password=password)
    assert response.status_code == 201, response.json()
    assert User.objects.get().check_password(password)


# ---- login -------------------------------------------------------------------------------------------


@pytest.mark.django_db
def test_login_verified_account(make_user, browser):
    user = account(make_user)
    response = browser.login("MEMBER@example.com")
    assert response.status_code == 200
    assert response["Cache-Control"] == NO_STORE
    body = response.json()
    assert set(body) == {"user", "email_verification_required"}
    assert body["email_verification_required"] is False
    assert body["user"]["id"] == str(user.pk) and body["user"]["email_verified"] is True
    assert Session.objects.get(session_key=browser.session_key).user_id == user.pk


@pytest.mark.django_db
def test_login_unverified_account_gets_restricted_session(make_user, browser):
    account(make_user, verified=False)
    response = browser.login("member@example.com")
    assert response.status_code == 200
    assert response.json()["email_verification_required"] is True
    assert browser.get("me").status_code == 200
    with override_settings(ROOT_URLCONF="apps.accounts.auth_test_urls"):
        assert browser.client.get("/api/v1/test-protected").status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize("email, password", [("member@example.com", "a wrong passphrase!!"), ("nobody@example.com", PASSWORD)])
def test_login_invalid_credentials_is_401(make_user, browser, email, password):
    account(make_user)
    response = browser.login(email, password)
    assert response.status_code == 401
    assert response.json() == {"code": "AUTHENTICATION_ERROR", "message": "Authentication is required."}
    assert browser.session_key is None or SESSION_KEY not in browser.session()


@pytest.mark.django_db
def test_login_disabled_account_is_401(make_user, browser):
    account(make_user, is_active=False)
    assert browser.login("member@example.com").status_code == 401


@pytest.mark.django_db
def test_login_social_only_account_without_password_is_401(make_user, browser):
    user = make_user("social@example.com")
    user.set_unusable_password()
    user.save()
    assert browser.login("social@example.com", "").status_code == 400
    assert browser.login("social@example.com", "anything at all").status_code == 401


@pytest.mark.django_db
@pytest.mark.parametrize(
    "body",
    [{}, {"email": "member@example.com"}, {"password": PASSWORD}, {"email": "bad", "password": PASSWORD},
     {"email": "member@example.com", "password": PASSWORD, "remember": True}, {"email": 1, "password": PASSWORD}],
)
def test_login_validation_errors_are_400(make_user, browser, body):
    account(make_user)
    response = browser.post("login", body)
    assert response.status_code == 400
    assert response.json()["code"] == "VALIDATION_ERROR"


@pytest.mark.django_db
def test_login_does_not_apply_the_new_password_policy(make_user, browser):
    account(make_user, password="short")  # a credential set before a policy change still works
    assert browser.login("member@example.com", "short").status_code == 200


@pytest.mark.django_db
def test_login_rotates_session_and_csrf_and_deletes_the_old_session(make_user, browser):
    account(make_user)
    put_intent(browser)
    old_key, old_csrf = browser.session_key, browser.token()
    browser.login("member@example.com")
    assert browser.session_key and browser.session_key != old_key
    assert not Session.objects.filter(session_key=old_key).exists()
    assert browser.client.cookies["csrftoken"].value != old_csrf


@pytest.mark.django_db
def test_login_as_another_account_replaces_the_previous_login(make_user, browser):
    first = account(make_user, "first@example.com")
    second = account(make_user, "second@example.com")
    browser.login("first@example.com")
    first_key = browser.session_key
    assert browser.login("second@example.com").status_code == 200
    assert not Session.objects.filter(session_key=first_key).exists()
    assert browser.get("me").json()["id"] == str(second.pk)
    assert not Session.objects.filter(user=first).exists()


# ---- invitation intent across authentication --------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("operation", ["signup", "login", "login-unverified"])
def test_valid_invitation_intent_survives_rotation_and_nothing_else_does(make_user, browser, operation):
    intent = put_intent(browser, extra={"stale_state": "dropped"})
    old_key = browser.session_key
    if operation == "signup":
        response = browser.signup()
    else:
        account(make_user, verified=operation == "login")
        response = browser.login("member@example.com")
    assert response.status_code in (200, 201)
    session = browser.session()
    assert browser.session_key != old_key
    assert get_invitation_intent(session) == intent
    assert "stale_state" not in session


@pytest.mark.django_db
def test_malformed_invitation_intent_is_not_carried_forward(make_user, browser):
    account(make_user)
    browser.csrf()
    session = browser.client.session
    session[INVITATION_INTENT_SESSION_KEY] = {"invitation_id": "not-a-uuid", "generation": 1, "token": "secret"}
    session.save()
    browser.client.cookies["sessionid"] = session.session_key
    browser.login("member@example.com")
    assert INVITATION_INTENT_SESSION_KEY not in browser.session()


@pytest.mark.django_db
def test_intent_survives_switching_accounts_in_the_same_browser(make_user, browser):
    account(make_user, "first@example.com")
    account(make_user, "second@example.com")
    browser.login("first@example.com")
    session = browser.client.session
    intent = set_invitation_intent(session, uuid.uuid4(), 1)
    session.save()
    browser.login("second@example.com")
    assert get_invitation_intent(browser.session()) == intent


# ---- logout ------------------------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("verified", [True, False])
def test_logout_flushes_session_and_intent_and_expires_cookie(make_user, browser, verified):
    account(make_user, verified=verified)
    browser.login("member@example.com")
    session = browser.client.session
    set_invitation_intent(session, uuid.uuid4(), 1)
    session.save()
    key = browser.session_key

    response = browser.post("logout")
    assert response.status_code == 204
    assert response.content == b""
    assert response.cookies["sessionid"].value == ""
    assert "1970" in response.cookies["sessionid"]["expires"]
    assert not Session.objects.filter(session_key=key).exists()
    assert browser.get("me").status_code == 401


@pytest.mark.django_db
def test_logout_without_session_is_401(browser):
    browser.csrf()
    response = browser.post("logout")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_ERROR"


@pytest.mark.django_db
def test_logout_revokes_only_the_current_session(make_user):
    account(make_user)
    laptop, phone = Browser(), Browser()
    laptop.login("member@example.com")
    phone.login("member@example.com")
    assert laptop.post("logout").status_code == 204
    assert phone.get("me").status_code == 200


# ---- getCurrentUser ---------------------------------------------------------------------------------


@pytest.mark.django_db
def test_current_user(make_user, browser):
    user = account(make_user, name="Ada")
    SocialAccount.objects.create(user=user, provider="google", uid="google-uid-1")
    browser.login("member@example.com")
    response = browser.get("me")
    assert response.status_code == 200
    assert response["Cache-Control"] == NO_STORE
    body = response.json()
    assert body == {
        "id": str(user.pk),
        "email": "member@example.com",
        "name": "Ada",
        "email_verified": True,
        "google_linked": True,
        "created_at": body["created_at"],
    }
    assert body["created_at"].endswith("Z")


@pytest.mark.django_db
def test_current_user_requires_a_session(browser):
    response = browser.get("me")
    assert response.status_code == 401
    assert response["Cache-Control"] == NO_STORE


@pytest.mark.django_db
def test_current_user_after_account_disabled_is_401(make_user, browser):
    user = account(make_user)
    browser.login("member@example.com")
    User.objects.filter(pk=user.pk).update(is_active=False)
    assert browser.get("me").status_code == 401


# ---- rate limits (ADR-016) ---------------------------------------------------------------------------


def assert_throttled(response):
    assert response.status_code == 429
    assert response.json()["code"] == "RATE_LIMITED"
    assert int(response["Retry-After"]) >= 1
    assert response["Cache-Control"] == NO_STORE


@pytest.mark.django_db
def test_login_failures_per_address_are_limited_even_with_the_right_password(make_user, browser):
    account(make_user)
    for _ in range(5):
        assert browser.login("member@example.com", "a wrong passphrase!!").status_code == 401
    assert_throttled(browser.login("member@example.com"))
    assert browser.session_key is None or SESSION_KEY not in browser.session()


@pytest.mark.django_db
def test_login_failure_limit_counts_unknown_addresses_identically(browser):
    for _ in range(5):
        assert browser.login("ghost@example.com", "a wrong passphrase!!").status_code == 401
    response = browser.login("ghost@example.com")
    assert_throttled(response)


@pytest.mark.django_db
def test_successful_login_clears_the_failure_count(make_user, browser):
    account(make_user)
    for _ in range(4):
        browser.login("member@example.com", "a wrong passphrase!!")
    assert browser.login("member@example.com").status_code == 200
    for _ in range(5):
        assert browser.login("member@example.com", "a wrong passphrase!!").status_code == 401


@pytest.mark.django_db
def test_login_failures_from_other_clients_do_not_lock_the_account(make_user):
    """No lockout: the limit delays guesses for the address; it never disables the account."""
    user = account(make_user)
    attacker = Browser("198.51.100.66")
    for _ in range(6):
        attacker.login("member@example.com", "a wrong passphrase!!")
    user.refresh_from_db()
    assert user.is_active


@pytest.mark.django_db
def test_login_per_ip_limit(make_user, browser):
    for i in range(30):
        assert browser.login(f"user{i}@example.com", "a wrong passphrase!!").status_code == 401
    assert_throttled(browser.login("user99@example.com"))
    assert Browser("198.51.100.1").login("user99@example.com", "a wrong passphrase!!").status_code == 401


@pytest.mark.django_db
def test_signup_per_address_limit(make_user, browser):
    account(make_user)
    for _ in range(3):
        assert Browser(f"198.51.100.{_ + 1}").signup(email="member@example.com").status_code == 409
    assert_throttled(browser.signup(email="member@example.com"))


@pytest.mark.django_db
def test_signup_per_ip_limit(browser):
    for i in range(10):
        assert browser.signup(email=f"user{i}@example.com").status_code == 201
    assert_throttled(browser.signup(email="user99@example.com"))
    assert User.objects.count() == 10


@pytest.mark.django_db
def test_invalid_requests_still_count_toward_the_ip_limit(browser):
    for _ in range(10):
        assert browser.post("signup", {"email": "bad"}).status_code == 400
    assert_throttled(browser.post("signup", {"email": "bad"}))


@pytest.mark.django_db
def test_rate_limit_storage_failure_fails_closed(make_user, browser):
    account(make_user)
    browser.csrf()
    with mock.patch("apps.ratelimit.limiter.connection.cursor", side_effect=DatabaseError("down")):
        with pytest.raises(DatabaseError):
            browser.login("member@example.com")
        with pytest.raises(DatabaseError):
            browser.signup()
    assert User.objects.count() == 1


@pytest.mark.django_db
def test_rate_limit_counters_store_no_address_or_ip(browser):
    browser.signup(email="private.person@example.com")
    stored = repr(list(RateLimitBucket.objects.values()))
    assert "private.person" not in stored and "203.0.113" not in stored


@pytest.mark.django_db
def test_allauth_rate_limiter_is_disabled():
    from allauth.account import app_settings

    assert app_settings.RATE_LIMITS == {}


# ---- secrets never persisted or logged --------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_no_password_or_bearer_reaches_persistence_or_logs(browser, provider, caplog):
    caplog.set_level(logging.DEBUG)
    response = browser.signup(email="private.person@example.com")
    assert response.status_code == 201
    [message] = provider.sent
    bearer = message.text_body.split("#verifier=")[1].split()[0]
    persisted = repr(list(EmailVerificationBearer.objects.values())) + repr(list(EmailDelivery.objects.values()))
    persisted += repr(list(Session.objects.values_list("session_data", flat=True)))
    persisted += repr(list(RateLimitBucket.objects.values()))
    for haystack in (persisted, caplog.text, response.content.decode()):
        for secret in (bearer, PASSWORD, "verify-email"):
            assert secret not in haystack
    assert "private.person" not in repr(list(EmailDelivery.objects.values()))

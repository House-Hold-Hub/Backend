"""requestPasswordReset, resetPassword and changePassword (Backend#36).

Against the contract, the Identity PRD (IA-US-004, IA-FR-010/011/014), ADR-011 (revocation matrix), ADR-015
(post-commit delivery, no secret in delivery metadata) and ADR-016 (password policy, bearer constants, rate limits).
The tests commit for real (``transaction=True``): the reset email is submitted after the response is closed.
"""

import datetime
import logging
import threading
import time
import uuid

import pytest
from allauth.account.models import EmailAddress
from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import override_settings
from django.utils import timezone

from apps.accounts import password_recovery, views
from apps.accounts.models import EmailVerificationBearer, PasswordResetBearer, Session
from apps.accounts.sessions import get_invitation_intent
from apps.accounts.test_auth_api import NO_STORE, PASSWORD, Browser, account, assert_throttled, put_intent
from apps.accounts.test_email_lifecycle import link_of
from apps.accounts.verification import bearer_digest
from apps.email_delivery import service
from apps.email_delivery.adapter import ProviderNotConfigured, ProviderRejected, ProviderTimeout
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.testing import RecordingProvider
from apps.ratelimit import limiter
from apps.ratelimit.models import RateLimitBucket

User = get_user_model()
pytestmark = pytest.mark.django_db(transaction=True)

NEW_PASSWORD = "another long passphrase!"
ACKNOWLEDGEMENT = {"message": views.RESET_REQUESTED_MESSAGE}
INVALID_VERIFIER = {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed.",
    "fields": {"verifier": ["The verifier is invalid or has expired."]},
}
WRONG_CURRENT = {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed.",
    "fields": {"current_password": ["The current password is incorrect."]},
}


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    provider = RecordingProvider()
    monkeypatch.setattr(service, "get_provider", lambda: provider)
    return provider


@pytest.fixture(autouse=True)
def no_response_floor(settings):
    settings.AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS = 0


@pytest.fixture
def browser():
    return Browser()


def forgot(browser, email="member@example.com"):
    response = browser.post("forgot-password", {"email": email})
    service.join_background_submissions()  # the provider call runs on its own thread after the response
    return response


def reset(browser, bearer, password=NEW_PASSWORD):
    return browser.post("reset-password", {"verifier": bearer, "new_password": password})


def change(browser, current=PASSWORD, new=NEW_PASSWORD):
    return browser.post("change-password", {"current_password": current, "new_password": new})


def reset_bearer(user, bearer=None, *, email=None, expires_in=3600, **fields):
    """A reset bearer with known plaintext, stored the way issuance stores it."""
    bearer = bearer or f"reset-{uuid.uuid4()}"
    PasswordResetBearer.objects.create(
        user=user,
        email=email or user.email,
        digest=bearer_digest(bearer),
        expires_at=timezone.now() + datetime.timedelta(seconds=expires_in),
        **fields,
    )
    return bearer


def mailed_bearer(provider, index=-1):
    return link_of(provider.sent[index])[1]


def is_logged_in(browser):
    return browser.get("me").status_code == 200


def sessions_of(user):
    return set(Session.objects.filter(user=user).values_list("session_key", flat=True))


def password_works(email, password):
    user = User.objects.get(email=email)
    return user.check_password(password)


# ---- requestPasswordReset ----------------------------------------------------------------------------


def test_request_for_an_existing_account_mails_a_fragment_link_and_stores_only_the_digest(make_user, browser, provider):
    user = account(make_user)
    response = forgot(browser)
    assert response.status_code == 202
    assert response.json() == ACKNOWLEDGEMENT
    assert response["Cache-Control"] == NO_STORE

    (message,) = provider.sent
    assert message.to == "member@example.com"
    base, bearer = link_of(message)
    assert base.endswith(settings.FRONTEND_PASSWORD_RESET_PATH)
    assert "?" not in message.text_body.split("http", 1)[1].split()[0]
    assert len(bearer) >= 43  # 256 bits, base64url

    record = PasswordResetBearer.objects.get()
    assert record.user_id == user.pk and record.email == user.email
    assert record.digest == bearer_digest(bearer) and record.digest != bearer
    lifetime = (record.expires_at - record.created_at).total_seconds()
    assert lifetime == pytest.approx(settings.AUTH_PASSWORD_RESET_LIFETIME_SECONDS, abs=5) == pytest.approx(3600, abs=5)
    delivery = EmailDelivery.objects.get()
    assert (delivery.template, delivery.subject_type, delivery.subject_id) == ("password-reset", "password-reset-bearer", record.pk)
    assert delivery.status == EmailDelivery.Status.ACCEPTED


def test_request_issues_nothing_for_an_unknown_address(browser, provider):
    response = forgot(browser, "nobody@example.com")
    assert response.status_code == 202 and response.json() == ACKNOWLEDGEMENT
    assert provider.sent == []
    assert not PasswordResetBearer.objects.exists() and not EmailDelivery.objects.exists()


def test_every_valid_request_gets_the_same_status_body_and_headers(make_user, provider):
    account(make_user, "member@example.com")
    account(make_user, "unverified@example.com", verified=False)
    disabled = account(make_user, "disabled@example.com")
    User.objects.filter(pk=disabled.pk).update(is_active=False)
    google_only = make_user("google@example.com")
    assert not google_only.has_usable_password()

    responses = [
        forgot(Browser(), email)
        for email in (
            "member@example.com",
            "unverified@example.com",
            "disabled@example.com",
            "google@example.com",
            "unknown@example.com",
            "  MEMBER@Example.COM ",
        )
    ]
    signatures = {
        (r.status_code, r.content, r["Content-Type"], r["Cache-Control"], tuple(sorted(r.cookies))) for r in responses
    }
    assert len(signatures) == 1
    # Only the accounts that can reset a password were mailed (unverified ones included: they own the mailbox).
    assert sorted(m.to for m in provider.sent) == ["member@example.com", "member@example.com", "unverified@example.com"]
    assert PasswordResetBearer.objects.filter(user__email__in=["disabled@example.com", "google@example.com"]).count() == 0


@pytest.mark.parametrize(
    ("outcome", "status", "error_class"),
    [
        (ProviderRejected("secret recipient@example.com"), EmailDelivery.Status.FAILED, "rejected"),
        (ProviderTimeout("slow"), EmailDelivery.Status.UNKNOWN, "timeout"),
        (RuntimeError("boom https://x/#verifier=abc"), EmailDelivery.Status.UNKNOWN, "unexpected"),
        (ProviderNotConfigured(), EmailDelivery.Status.FAILED, "not_configured"),
    ],
)
def test_provider_failure_is_invisible_to_the_caller_and_recorded_on_the_delivery(
    make_user, browser, provider, outcome, status, error_class
):
    account(make_user)
    provider.outcome = outcome
    failed = forgot(browser)
    unknown = forgot(browser, "unknown@example.com")
    assert (failed.status_code, failed.content) == (unknown.status_code, unknown.content) == (202, failed.content)
    assert failed.json() == ACKNOWLEDGEMENT
    delivery = EmailDelivery.objects.get()
    assert (delivery.status, delivery.error_class) == (status, error_class)
    assert PasswordResetBearer.objects.get().is_usable(timezone.now())  # a new request recovers


def test_the_provider_is_called_only_after_the_response_is_closed(make_user, browser, provider, monkeypatch):
    """A slow provider cannot delay the response of an existing account (timing enumeration)."""
    account(make_user)
    held = []
    monkeypatch.setattr(views.DeferredWorkResponse, "close", lambda self: held.append(self))
    response = forgot(browser)
    assert response.status_code == 202
    assert provider.sent == []
    assert EmailDelivery.objects.get().status == EmailDelivery.Status.PENDING  # committed, not yet submitted

    held[0].deferred.run()
    held[0].deferred.run()  # idempotent: never submitted twice
    assert len(provider.sent) == 1
    assert EmailDelivery.objects.get().status == EmailDelivery.Status.ACCEPTED


def test_a_slow_provider_call_does_not_hold_the_request_or_its_worker(make_user, browser, provider):
    """The bounded call runs on another thread: the closed response returns while the provider is still busy."""
    account(make_user)
    started, release = threading.Event(), threading.Event()

    def slow(message):
        started.set()
        assert release.wait(10)

    provider.outcome = slow
    began = time.monotonic()
    response = browser.post("forgot-password", {"email": "member@example.com"})
    returned_in = time.monotonic() - began
    assert response.status_code == 202
    assert started.wait(10)  # the submission is under way ...
    assert returned_in < 5  # ... and the request did not wait for it
    assert EmailDelivery.objects.get().status == EmailDelivery.Status.SUBMITTING
    release.set()
    service.join_background_submissions()
    assert EmailDelivery.objects.get().status == EmailDelivery.Status.ACCEPTED


def _signature(response):
    return (response.status_code, response.content, response["Content-Type"], response["Cache-Control"], tuple(sorted(response.cookies)))


def test_overload_cannot_tell_an_existing_account_from_an_unknown_one(make_user, provider, settings):
    """Every background slot busy: the burst is answered alike, and only the delivery records differ."""
    settings.EMAIL_DELIVERY = {**settings.EMAIL_DELIVERY, "MAX_BACKGROUND_SUBMISSIONS": 1}
    for name in ("busy", "a", "b"):
        account(make_user, f"{name}@example.com")
    arrived, release = threading.Event(), threading.Event()

    def block(_message):
        arrived.set()
        assert release.wait(10)

    provider.outcome = block
    first = Browser().post("forgot-password", {"email": "busy@example.com"})
    assert arrived.wait(10)  # the only slot is now held by a slow provider call
    calls_before = len(provider.calls)

    burst = [
        Browser().post("forgot-password", {"email": email})
        for email in ("a@example.com", "b@example.com", "unknown1@example.com", "unknown2@example.com")
    ]
    assert {_signature(r) for r in [first, *burst]} == {_signature(first)}
    assert len(provider.calls) == calls_before  # nothing more was submitted while saturated
    refused = EmailDelivery.objects.filter(status=EmailDelivery.Status.FAILED, error_class="not_submitted")
    assert refused.count() == 2  # recorded for the two real accounts, invisible to their callers
    assert len(service._background_threads) == 1  # no thread pile-up

    release.set()
    service.join_background_submissions()
    assert EmailDelivery.objects.filter(status=EmailDelivery.Status.ACCEPTED).count() == 1
    # A refused account recovers with a new request once a slot is free.
    assert forgot(Browser(), "a@example.com").status_code == 202
    assert EmailDelivery.objects.filter(status=EmailDelivery.Status.ACCEPTED).count() == 2


def test_a_thread_that_cannot_start_does_not_change_the_response(make_user, browser, provider, monkeypatch):
    account(make_user)

    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    existing = forgot(browser)
    unknown = forgot(browser, "unknown@example.com")
    assert _signature(existing) == _signature(unknown) and existing.status_code == 202
    assert provider.sent == []
    assert EmailDelivery.objects.get().error_class == "not_submitted"


def test_a_request_that_rolls_back_queues_and_sends_nothing(make_user, browser, provider, monkeypatch):
    account(make_user)

    def fail(*args, **kwargs):
        raise RuntimeError("storage failure")

    monkeypatch.setattr(password_recovery, "queue_email", fail)
    browser.client.raise_request_exception = False
    assert forgot(browser).status_code == 500
    assert provider.sent == [] and not PasswordResetBearer.objects.exists()


def test_responses_take_at_least_the_configured_floor_for_every_address(make_user, settings):
    account(make_user)
    settings.AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS = 0.4
    for email in ("member@example.com", "unknown@example.com"):
        started = time.monotonic()
        assert forgot(Browser(), email).status_code == 202
        assert time.monotonic() - started >= 0.39


def test_the_floor_does_not_delay_requests_that_are_refused(browser, settings):
    settings.AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS = 5
    started = time.monotonic()
    assert browser.post("forgot-password", {"email": "not-an-email"}).status_code == 400
    assert time.monotonic() - started < 2


def test_a_new_request_supersedes_the_previous_bearer(make_user, browser, provider):
    account(make_user)
    forgot(browser)
    forgot(browser)
    first, second = (mailed_bearer(provider, 0), mailed_bearer(provider, 1))
    assert first != second
    assert PasswordResetBearer.objects.filter(superseded_at__isnull=True).count() == 1
    assert reset(browser, first).json() == INVALID_VERIFIER
    assert reset(browser, second).status_code == 204


def test_address_limit_counts_unknown_addresses_and_answers_alike(make_user, browser):
    account(make_user)
    for email in ("member@example.com", "unknown@example.com"):
        for _ in range(3):
            assert forgot(browser, email).status_code == 202
        existing_or_not = forgot(browser, email)
        assert_throttled(existing_or_not)
    # One address's limit does not block another, and the key is the normalized address.
    assert forgot(browser, "other@example.com").status_code == 202
    assert_throttled(forgot(browser, "  UNKNOWN@example.com"))


def test_client_ip_limit(browser):
    for index in range(20):
        assert forgot(browser, f"user{index}@example.com").status_code == 202
    assert_throttled(forgot(browser, "one.more@example.com"))
    assert forgot(Browser("203.0.113.99"), "one.more@example.com").status_code == 202  # another client is unaffected


def test_throttled_responses_are_identical_for_existing_and_unknown_addresses(make_user):
    account(make_user)
    results = []
    for email in ("member@example.com", "unknown@example.com"):
        browser = Browser()
        for _ in range(3):
            forgot(browser, email)
        throttled = forgot(browser, email)
        results.append((throttled.status_code, throttled.content, throttled["Retry-After"] is not None))
    assert results[0] == results[1]


def test_rate_limit_keys_hide_the_address(make_user, browser):
    account(make_user)
    forgot(browser)
    assert "member" not in repr(list(RateLimitBucket.objects.values()))


@pytest.mark.parametrize(
    "body",
    [{}, {"email": ""}, {"email": "not-an-email"}, {"email": 5}, {"email": None}, {"email": "a@example.com", "extra": 1}, []],
)
def test_malformed_requests_are_400_and_issue_nothing(browser, provider, body):
    response = browser.post("forgot-password", body)
    assert response.status_code == 400 and response.json()["code"] == "VALIDATION_ERROR"
    assert provider.sent == [] and not PasswordResetBearer.objects.exists()


def test_malformed_json_is_400(browser):
    assert browser.post("forgot-password", raw="{").status_code == 400


@pytest.mark.parametrize("path", ["forgot-password", "reset-password"])
def test_public_operations_require_csrf(make_user, browser, path):
    account(make_user)
    response = browser.post(path, {"email": "member@example.com", "verifier": "x", "new_password": NEW_PASSWORD}, csrf=False)
    assert response.status_code == 403 and response.json()["code"] == "AUTHORIZATION_ERROR"
    assert not PasswordResetBearer.objects.exists()


def test_a_restricted_unverified_session_may_request_a_reset(make_user, browser, provider):
    browser.signup(email="new.user@example.com")
    provider.sent.clear()
    assert forgot(browser, "new.user@example.com").status_code == 202
    assert len(provider.sent) == 1


# ---- resetPassword -----------------------------------------------------------------------------------


def test_reset_changes_the_password_and_the_bearer_is_single_use(make_user, browser, provider):
    user = account(make_user)
    forgot(browser)
    bearer = mailed_bearer(provider)

    response = reset(browser, bearer)
    assert response.status_code == 204 and response.content == b""
    assert response["Cache-Control"] == NO_STORE
    assert password_works(user.email, NEW_PASSWORD) and not password_works(user.email, PASSWORD)
    assert PasswordResetBearer.objects.get().consumed_at is not None
    assert browser.session_key is None  # the bearer never logs anyone in
    assert not is_logged_in(browser)

    replay = reset(browser, bearer, "yet another long passphrase")
    assert replay.status_code == 400 and replay.json() == INVALID_VERIFIER
    assert password_works(user.email, NEW_PASSWORD)

    assert Browser().login(user.email, NEW_PASSWORD).status_code == 200
    assert Browser().login(user.email, PASSWORD).status_code == 401


def test_reset_revokes_every_session_including_the_callers(make_user, provider):
    user = account(make_user)
    phone, laptop, resetter = Browser(), Browser(), Browser()
    for browser in (phone, laptop, resetter):
        assert browser.login(user.email).status_code == 200
    assert len(sessions_of(user)) == 3
    forgot(phone)
    bearer = mailed_bearer(provider)

    assert reset(resetter, bearer).status_code == 204
    assert sessions_of(user) == set()
    for browser in (phone, laptop, resetter):
        assert not is_logged_in(browser)
    assert Browser().login(user.email, NEW_PASSWORD).status_code == 200


def test_a_session_created_from_the_old_password_is_inert_after_the_reset(make_user, provider):
    """The authentication hash backs the revocation: a session written after the commit is flushed on use."""
    user = account(make_user)
    stale = Browser()
    stale.login(user.email)
    stale_key = stale.session_key
    forgot(Browser())
    assert reset(Browser(), mailed_bearer(provider)).status_code == 204
    # Put the revoked session back, as a login racing the reset could have written it after the commit.
    store = stale.client.session.__class__()
    store.update({SESSION_KEY: str(user.pk), "_auth_user_backend": settings.AUTHENTICATION_BACKENDS[0], "_auth_user_hash": "stale"})
    store.create()
    assert store.session_key is not None
    stale.client.cookies["sessionid"] = store.session_key
    assert stale_key != store.session_key
    assert not is_logged_in(stale)


@pytest.mark.parametrize(
    "kind", ["unknown", "expired", "consumed", "superseded", "email_changed", "other_purpose", "disabled"]
)
def test_every_unusable_bearer_gets_the_same_400_and_changes_nothing(make_user, browser, kind):
    user = account(make_user)
    bearer = f"reset-{uuid.uuid4()}"
    now = timezone.now()
    if kind == "other_purpose":
        EmailVerificationBearer.objects.create(
            user=user, email=user.email, digest=bearer_digest(bearer), expires_at=now + datetime.timedelta(hours=1)
        )
    elif kind != "unknown":
        fields: dict[str, dict] = {"expired": {"expires_in": -1}, "consumed": {"consumed_at": now}, "superseded": {"superseded_at": now}}
        reset_bearer(user, bearer, **fields.get(kind, {}))
        if kind == "email_changed":
            User.objects.filter(pk=user.pk).update(email="moved@example.com")
        if kind == "disabled":
            User.objects.filter(pk=user.pk).update(is_active=False)
    before = User.objects.get(pk=user.pk).password

    response = reset(browser, bearer)
    assert response.status_code == 400 and response.json() == INVALID_VERIFIER
    assert User.objects.get(pk=user.pk).password == before


def test_a_blank_bearer_is_a_field_error(browser):
    response = reset(browser, "")
    assert response.status_code == 400 and list(response.json()["fields"]) == ["verifier"]


def test_a_weak_password_is_a_retryable_field_error(make_user, browser):
    user = account(make_user, name="Maria Rossi")
    bearer = reset_bearer(user)
    cases = {
        "short": "x" * 14,
        "long": "x" * 129,
        "common": min(p for p in _common_passwords() if len(p) >= 15),
        "similar": "member@example.com",
        "similar_name": "maria rossi maria",
    }
    for password in cases.values():
        response = reset(browser, bearer, password)
        assert response.status_code == 400
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR" and "new_password" in body["fields"] and "verifier" not in body["fields"]
        assert password not in response.content.decode()
    assert not PasswordResetBearer.objects.get().consumed_at
    assert reset(browser, bearer, NEW_PASSWORD).status_code == 204  # the same bearer, now with a good password


def _common_passwords():
    from django.contrib.auth.password_validation import CommonPasswordValidator

    return [p for p in CommonPasswordValidator().passwords if p.isascii() and p.isalnum()]


@pytest.mark.parametrize("password", ["Ab1!" * 4, "x y" * 5, "ж" * 15, "🔐" * 15, "q7#" * 42 + "ab", "z" * 15 + " "])
def test_passwords_are_counted_in_code_points_and_accepted_as_entered(make_user, browser, password):
    user = account(make_user)
    assert len(password) <= 128
    assert reset(browser, reset_bearer(user), password).status_code == 204
    assert password_works(user.email, password)


def test_the_policy_bounds_are_exact(make_user, browser):
    user = account(make_user)
    bearer = reset_bearer(user)
    assert reset(browser, bearer, "🔐" * 14).status_code == 400
    assert reset(browser, bearer, "🔐" * 129).status_code == 400
    assert reset(browser, bearer, "qz" * 64).status_code == 204  # exactly 128


def test_an_account_without_a_usable_password_cannot_be_reset(make_user, browser):
    user = make_user("google@example.com")
    bearer = reset_bearer(user)
    response = reset(browser, bearer)
    assert response.status_code == 409 and response.json()["code"] == "CONFLICT"
    assert not User.objects.get(pk=user.pk).has_usable_password()
    assert not PasswordResetBearer.objects.get().consumed_at


def test_reset_does_not_verify_the_email_or_log_in(make_user, browser, provider):
    user = account(make_user, "unverified@example.com", verified=False)
    forgot(browser, user.email)
    assert reset(browser, mailed_bearer(provider)).status_code == 204
    assert not EmailAddress.objects.get(user=user).verified
    assert browser.session_key is None


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"verifier": "x"},
        {"new_password": NEW_PASSWORD},
        {"verifier": 5, "new_password": NEW_PASSWORD},
        {"verifier": "x", "new_password": 5},
        {"verifier": "x", "new_password": NEW_PASSWORD, "email": "a@example.com"},
    ],
)
def test_malformed_reset_requests_are_400(make_user, browser, body):
    account(make_user)
    response = browser.post("reset-password", body)
    assert response.status_code == 400 and response.json()["code"] == "VALIDATION_ERROR"


def test_reset_requests_are_limited_per_client_ip(browser):
    for _ in range(20):
        assert reset(browser, "unknown-bearer").status_code == 400
    assert_throttled(reset(browser, "unknown-bearer"))
    assert reset(Browser("203.0.113.99"), "unknown-bearer").status_code == 400


def test_the_bearer_is_neither_trimmed_nor_normalized(make_user, browser):
    user = account(make_user)
    bearer = reset_bearer(user)
    assert reset(browser, f" {bearer}").status_code == 400
    assert reset(browser, bearer.upper()).status_code == 400
    assert reset(browser, bearer).status_code == 204


# ---- changePassword ----------------------------------------------------------------------------------


def test_change_rotates_the_current_session_and_revokes_the_others(make_user):
    user = account(make_user)
    phone, laptop = Browser(), Browser()
    for browser in (phone, laptop):
        assert browser.login(user.email).status_code == 200
    old_key, other_key = laptop.session_key, phone.session_key
    intent = put_intent(laptop, extra={"stale": "dropped"})
    old_key = laptop.session_key
    old_csrf = laptop.client.cookies["csrftoken"].value

    response = change(laptop)
    assert response.status_code == 204 and response.content == b""
    assert response["Cache-Control"] == NO_STORE
    new_key = response.cookies["sessionid"].value
    assert new_key and new_key != old_key
    assert response.cookies["sessionid"]["httponly"]
    assert sessions_of(user) == {new_key}
    assert Session.objects.filter(session_key__in=[old_key, other_key]).count() == 0

    assert is_logged_in(laptop)
    assert not is_logged_in(phone)
    session = laptop.client.session
    assert get_invitation_intent(session) == intent
    assert "stale" not in session
    assert laptop.client.cookies["csrftoken"].value != old_csrf
    assert password_works(user.email, NEW_PASSWORD) and not password_works(user.email, PASSWORD)
    # The preserved session can still make unsafe requests and the old password no longer logs in.
    assert change(laptop, NEW_PASSWORD, "a third long passphrase!").status_code == 204
    assert Browser().login(user.email, PASSWORD).status_code == 401


@pytest.mark.parametrize("current", ["a wrong passphrase!!", "x", " " + PASSWORD])
def test_a_wrong_current_password_is_a_400_and_changes_nothing(make_user, current):
    user = account(make_user)
    browser, other = Browser(), Browser()
    browser.login(user.email), other.login(user.email)
    keys = sessions_of(user)
    response = change(browser, current)
    assert response.status_code == 400 and response.json() == WRONG_CURRENT
    assert password_works(user.email, PASSWORD)
    assert sessions_of(user) == keys and is_logged_in(browser) and is_logged_in(other)


def test_the_current_password_has_no_length_bounds(make_user):
    """ADR-016: a later policy change must not make an existing credential unusable."""
    short = "short"
    user = account(make_user, password=short)
    browser = Browser()
    assert browser.login(user.email, short).status_code == 200
    assert change(browser, short).status_code == 204


def test_a_weak_new_password_changes_nothing(make_user):
    user = account(make_user)
    browser, other = Browser(), Browser()
    browser.login(user.email), other.login(user.email)
    for password in ("x" * 14, "x" * 129, "member@example.com"):
        response = change(browser, PASSWORD, password)
        assert response.status_code == 400 and "new_password" in response.json()["fields"]
    assert password_works(user.email, PASSWORD) and is_logged_in(other)


def test_change_requires_a_session_and_csrf(make_user, browser):
    user = account(make_user)
    anonymous = change(browser)
    assert anonymous.status_code == 401 and anonymous.json()["code"] == "AUTHENTICATION_ERROR"
    browser.login(user.email)
    assert browser.post("change-password", {"current_password": PASSWORD, "new_password": NEW_PASSWORD}, csrf=False).status_code == 403
    assert password_works(user.email, PASSWORD)


def test_change_is_closed_to_a_restricted_unverified_session(browser):
    browser.signup(email="new.user@example.com")
    response = change(browser)
    assert response.status_code == 403 and response.json()["code"] == "AUTHORIZATION_ERROR"
    assert password_works("new.user@example.com", PASSWORD)


def test_an_account_without_a_current_password_gets_409(make_user, browser):
    account(make_user)
    browser.login("member@example.com")
    User.objects.update(password="!unusable")
    session = browser.client.session
    session["_auth_user_hash"] = User.objects.get().get_session_auth_hash()
    session.save()
    response = change(browser)
    assert response.status_code == 409
    assert response.json() == {"code": "CONFLICT", "message": "The account has no current password."}
    assert not User.objects.get().has_usable_password() and is_logged_in(browser)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"current_password": PASSWORD},
        {"new_password": NEW_PASSWORD},
        {"current_password": 1, "new_password": NEW_PASSWORD},
        {"current_password": PASSWORD, "new_password": None},
        {"current_password": PASSWORD, "new_password": NEW_PASSWORD, "email": "a@example.com"},
    ],
)
def test_malformed_change_requests_are_400(make_user, browser, body):
    account(make_user)
    browser.login("member@example.com")
    response = browser.post("change-password", body)
    assert response.status_code == 400 and response.json()["code"] == "VALIDATION_ERROR"
    assert password_works("member@example.com", PASSWORD)


def test_change_declares_no_rate_limit(make_user):
    """The contract has no 429 for changePassword, so ADR-016 adds none."""
    user = account(make_user)
    browser = Browser()
    browser.login(user.email)
    assert {r.status_code for r in (change(browser, "a wrong passphrase!!") for _ in range(12))} == {400}
    assert change(browser).status_code == 204


def test_a_change_voids_a_reset_link_requested_earlier(make_user, provider):
    user = account(make_user)
    forgot(Browser())
    bearer = mailed_bearer(provider)
    browser = Browser()
    browser.login(user.email)
    assert change(browser).status_code == 204
    assert PasswordResetBearer.objects.get().superseded_at is not None
    assert reset(Browser(), bearer, "a fourth long passphrase!").json() == INVALID_VERIFIER
    assert password_works(user.email, NEW_PASSWORD)


def test_login_limits_do_not_apply_to_recovery_and_cannot_lock_the_account(make_user, provider):
    user = account(make_user)
    attacker = Browser()
    for _ in range(5):
        attacker.login(user.email, "a wrong passphrase!!")
    assert_throttled(attacker.login(user.email))
    forgot(Browser())  # recovery still works for the owner
    assert reset(Browser(), mailed_bearer(provider)).status_code == 204
    assert password_works(user.email, NEW_PASSWORD)


# ---- nothing secret is persisted, logged or echoed ------------------------------------------------------


def test_no_bearer_or_password_reaches_persistence_logs_or_responses(make_user, provider, caplog):
    caplog.set_level(logging.DEBUG)
    user = account(make_user, "private.person@example.com")
    responses = [forgot(Browser(), user.email), forgot(Browser(), "ghost@example.com")]
    bearer = mailed_bearer(provider)
    responses += [reset(Browser(), "wrong-bearer-value"), reset(Browser(), bearer, "weak"), reset(Browser(), bearer)]
    responses.append(reset(Browser(), bearer))
    changer = Browser()
    changer.login(user.email, NEW_PASSWORD)
    responses.append(change(changer, "a wrong current passphrase", "a different new passphrase"))

    persisted = "".join(
        repr(list(model.objects.values()))
        for model in (PasswordResetBearer, EmailDelivery, RateLimitBucket, Session)
    )
    secrets_ = (bearer, "wrong-bearer-value", NEW_PASSWORD, PASSWORD, "a wrong current passphrase", "a different new passphrase")
    for secret in secrets_:
        for haystack in (persisted, caplog.text, *(r.content.decode() for r in responses)):
            assert secret not in haystack
    deliveries = repr(list(EmailDelivery.objects.values()))
    assert "private.person" not in deliveries and "reset-password" not in deliveries
    assert "private.person" not in caplog.text and "ghost@example.com" not in caplog.text


# ---- ADR-016 constants and scope ---------------------------------------------------------------------------


def test_recovery_constants_match_adr_016():
    assert settings.AUTH_PASSWORD_RESET_LIFETIME_SECONDS == 3600
    limits = settings.AUTH_RATE_LIMITS
    assert limits["password_reset_ip"] == (("ip", 20, 3600),)
    assert limits["password_reset_email"] == (("email", 3, 3600),)
    assert limits["reset_password_ip"] == (("ip", 20, 300),)
    assert {rate.per for action in ("password_reset_ip", "password_reset_email", "reset_password_ip") for rate in limiter.rates_for(action)} == {"ip", "email"}


@override_settings(AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS=0.2)
def test_pad_response_waits_only_for_the_remaining_time(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(password_recovery.time, "sleep", sleeps.append)
    password_recovery.pad_response(time.monotonic() - 10)
    assert sleeps == []
    password_recovery.pad_response(time.monotonic())
    assert 0 < sleeps[0] <= 0.2

"""verifyEmail, resendEmailVerification, requestPrimaryEmailChange and verifyPrimaryEmailChange (Backend#35).

Against the contract and ADR-011 (verification gate, rotation and revocation), ADR-015 (recoverable delivery)
and ADR-016 (bearer constants, recent reauthentication, rate limits). One ``Browser`` per browser.
"""

import datetime
import logging
import threading
import uuid
from unittest import mock

import pytest
from allauth.account.authentication import AUTHENTICATION_METHODS_SESSION_KEY
from allauth.account.models import EmailAddress
from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.db import DatabaseError, connection
from django.test import override_settings
from django.utils import timezone

from apps.accounts import views
from apps.accounts.models import EmailVerificationBearer, PrimaryEmailChange, Session
from apps.accounts.sessions import PRIMARY_EMAIL_CHANGE_SESSION_KEY, get_invitation_intent, set_invitation_intent
from apps.accounts.test_auth_api import NO_STORE, Browser, account, assert_throttled, put_intent
from apps.accounts.verification import bearer_digest
from apps.email_delivery import service
from apps.email_delivery.adapter import ProviderRejected, ProviderTimeout
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.testing import RecordingProvider
from apps.ratelimit import limiter
from apps.ratelimit.models import RateLimitBucket

User = get_user_model()
INVALID_VERIFIER = {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed.",
    "fields": {"verifier": ["The verifier is invalid or has expired."]},
}
NO_COMPATIBLE_CHANGE = {"code": "CONFLICT", "message": "No compatible pending primary-email change can be completed."}
FORBIDDEN = {"code": "AUTHORIZATION_ERROR", "message": "You do not have permission to perform this action."}


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    provider = RecordingProvider()
    monkeypatch.setattr(service, "get_provider", lambda: provider)
    return provider


@pytest.fixture
def browser():
    return Browser()


def link_of(message):
    """(link without fragment, bearer) of the only link in an email."""
    link = next(word for word in message.text_body.split() if word.startswith("http"))
    base, _, fragment = link.partition("#")
    assert fragment.startswith("verifier=")
    return base, fragment.removeprefix("verifier=")


def issue_bearer(user, bearer=None, *, email=None, expires_in=3600, **fields):
    """An initial-verification bearer with known plaintext, stored the way issuance stores it."""
    bearer = bearer or f"bearer-{uuid.uuid4()}"
    EmailVerificationBearer.objects.create(
        user=user,
        email=email or user.email,
        digest=bearer_digest(bearer),
        expires_at=timezone.now() + datetime.timedelta(seconds=expires_in),
        **fields,
    )
    return bearer


def verify(browser, bearer):
    return browser.post("email/verify", {"verifier": bearer})


def request_change(browser, new_email="new.address@example.com"):
    return browser.post("email/change", {"new_email": new_email})


def verify_change(browser, bearer):
    return browser.post("email/change/verify", {"verifier": bearer})


def age_authentication(browser, seconds):
    """Make the session's last authentication ``seconds`` older, as if that much time had passed."""
    session = browser.client.session
    records = session[AUTHENTICATION_METHODS_SESSION_KEY]
    records[-1]["at"] -= seconds
    session[AUTHENTICATION_METHODS_SESSION_KEY] = records
    session.save()


def committed(capture, call):
    """Run a request and then its post-commit email submission (non-transactional tests)."""
    with capture(execute=True):
        response = call()
    return response


def protected_status(browser):
    with override_settings(ROOT_URLCONF="apps.accounts.auth_test_urls"):
        return browser.client.get("/api/v1/test-protected").status_code


# ---- verifyEmail ----------------------------------------------------------------------------------


@pytest.mark.django_db
def test_signup_bearer_verifies_and_upgrades_the_same_browser_session(browser, provider, django_capture_on_commit_callbacks):
    intent = put_intent(browser)
    committed(django_capture_on_commit_callbacks, browser.signup)
    base, bearer = link_of(provider.sent[0])
    assert base == "http://testserver/verify-email"
    user = User.objects.get()
    restricted_key, old_csrf = browser.session_key, browser.token()
    assert protected_status(browser) == 403

    response = verify(browser, bearer)
    assert response.status_code == 204
    assert response.content == b""
    assert response["Cache-Control"] == NO_STORE
    assert response.cookies["sessionid"].value  # rotated cookie (contract: only for the upgraded session)

    address = EmailAddress.objects.get(user=user)
    assert (address.email, address.primary, address.verified) == (user.email, True, True)
    record = EmailVerificationBearer.objects.get(user=user)
    assert record.consumed_at is not None and record.superseded_at is None
    # The restricted session was rotated, keeps its login and invitation intent, and is now unrestricted.
    assert browser.session_key != restricted_key
    assert not Session.objects.filter(session_key=restricted_key).exists()
    assert browser.session()[SESSION_KEY] == str(user.pk)
    assert get_invitation_intent(browser.session()) == intent
    assert browser.client.cookies["csrftoken"].value != old_csrf
    assert browser.get("me").json()["email_verified"] is True
    assert protected_status(browser) == 200


@pytest.mark.django_db
def test_cross_device_verification_creates_no_session_and_leaves_other_browsers_alone(make_user, browser):
    user = account(make_user, verified=False)
    signup_browser = Browser()
    signup_browser.login("member@example.com")
    signup_key = signup_browser.session_key
    bearer = issue_bearer(user)

    other_device = Browser(remote_addr="198.51.100.7")
    other_device.csrf()
    response = verify(other_device, bearer)
    assert response.status_code == 204
    assert "sessionid" not in response.cookies
    assert other_device.get("me").status_code == 401  # the bearer is not a login credential
    assert User.objects.get().is_email_verified
    # The originating browser's session is untouched (same key) and simply no longer restricted.
    assert signup_browser.session_key == signup_key
    assert protected_status(signup_browser) == 200


@pytest.mark.django_db
def test_verification_in_a_browser_signed_in_as_another_account_changes_nothing_there(make_user):
    target = account(make_user, "target@example.com", verified=False)
    account(make_user, "other@example.com")
    other = Browser()
    other.login("other@example.com")
    key = other.session_key

    assert verify(other, issue_bearer(target)).status_code == 204
    assert other.session_key == key
    assert other.get("me").json()["email"] == "other@example.com"
    assert User.objects.get(pk=target.pk).is_email_verified


@pytest.mark.django_db
def test_replayed_bearer_is_rejected_like_an_unknown_one(make_user, browser):
    user = account(make_user, verified=False)
    bearer = issue_bearer(user)
    browser.csrf()
    assert verify(browser, bearer).status_code == 204
    replay = verify(browser, bearer)
    assert replay.status_code == 400
    assert replay.json() == INVALID_VERIFIER
    assert verify(browser, "never-issued").json() == INVALID_VERIFIER


@pytest.mark.django_db
@pytest.mark.parametrize("state", ["unknown", "expired", "superseded", "consumed", "other-address", "disabled"])
def test_every_unusable_bearer_gets_the_same_400(make_user, browser, state):
    user = account(make_user, verified=False)
    bearer = "the-bearer"
    if state == "expired":
        issue_bearer(user, bearer, expires_in=-1)
    elif state == "superseded":
        issue_bearer(user, bearer, superseded_at=timezone.now())
    elif state == "consumed":
        issue_bearer(user, bearer, consumed_at=timezone.now())
    elif state == "other-address":
        issue_bearer(user, bearer, email="previous@example.com")
    elif state == "disabled":
        issue_bearer(user, bearer)
        User.objects.filter(pk=user.pk).update(is_active=False)
    browser.csrf()
    response = verify(browser, bearer)
    assert response.status_code == 400
    assert response.json() == INVALID_VERIFIER
    assert response["Cache-Control"] == NO_STORE
    assert not EmailAddress.objects.filter(verified=True).exists()


@pytest.mark.django_db
def test_bearer_of_an_already_verified_account_is_409_and_stays_unconsumed(make_user, browser):
    user = account(make_user)
    bearer = issue_bearer(user)
    browser.csrf()
    response = verify(browser, bearer)
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
    assert EmailVerificationBearer.objects.get().consumed_at is None


@pytest.mark.django_db
def test_primary_email_change_bearer_is_not_accepted_by_verify_email(make_user, browser):
    user = account(make_user, verified=False)
    PrimaryEmailChange.objects.create(
        user=user, new_email="x@example.com", digest=bearer_digest("change-bearer"),
        expires_at=timezone.now() + datetime.timedelta(hours=1),
    )
    browser.csrf()
    assert verify(browser, "change-bearer").json() == INVALID_VERIFIER


@pytest.mark.django_db
@pytest.mark.parametrize(
    "body, field",
    [({}, "verifier"), ({"verifier": 42}, "verifier"), ({"verifier": ""}, "verifier"), ({"verifier": "x", "extra": 1}, "extra")],
)
def test_verify_email_validation_errors_are_400(browser, body, field):
    browser.csrf()
    response = browser.post("email/verify", body)
    assert response.status_code == 400
    assert field in response.json()["fields"]


@pytest.mark.django_db
def test_verify_email_requires_csrf_and_post(make_user, browser):
    user = account(make_user, verified=False)
    bearer = issue_bearer(user)
    browser.csrf()
    assert browser.post("email/verify", {"verifier": bearer}, csrf=False).status_code == 403
    assert browser.get("email/verify").status_code == 405
    assert EmailVerificationBearer.objects.get().consumed_at is None


@pytest.mark.django_db
def test_verify_email_per_ip_limit_refuses_even_a_valid_bearer(make_user, browser):
    user = account(make_user, verified=False)
    bearer = issue_bearer(user)
    browser.csrf()
    for _ in range(20):
        assert verify(browser, "guess").status_code == 400
    assert_throttled(verify(browser, bearer))
    assert EmailVerificationBearer.objects.get().consumed_at is None
    assert verify(Browser(remote_addr="198.51.100.8"), bearer).status_code == 204


@pytest.mark.django_db(transaction=True)
def test_concurrent_uses_of_one_bearer_verify_exactly_once(make_user):
    user = account(make_user, verified=False)
    bearer = issue_bearer(user)
    browsers = [Browser(remote_addr=f"198.51.100.{i}") for i in range(6)]
    for b in browsers:
        b.csrf()
    barrier = threading.Barrier(len(browsers))
    statuses = [0] * len(browsers)

    def run(index):
        try:
            barrier.wait(timeout=10)
            statuses[index] = verify(browsers[index], bearer).status_code
        finally:
            connection.close()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(browsers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(statuses) == [204] + [400] * 5
    assert EmailAddress.objects.get(user=user).verified


@pytest.mark.django_db(transaction=True)
def test_verify_racing_resend_never_deadlocks_and_ends_consistent(make_user):
    user = account(make_user, verified=False)
    bearer = issue_bearer(user)
    signed_in = Browser()
    signed_in.login("member@example.com")
    stranger = Browser(remote_addr="198.51.100.9")
    stranger.csrf()
    barrier = threading.Barrier(2)
    results = {}

    def run(name, call):
        try:
            barrier.wait(timeout=10)
            results[name] = call().status_code
        finally:
            connection.close()

    threads = [
        threading.Thread(target=run, args=("verify", lambda: verify(stranger, bearer))),
        threading.Thread(target=run, args=("resend", lambda: signed_in.post("email/resend-verification"))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive(), "deadlock"
    verified = User.objects.get().is_email_verified
    if results["verify"] == 204:
        assert verified and results["resend"] == 409
        assert EmailVerificationBearer.objects.filter(consumed_at__isnull=True, superseded_at__isnull=True).count() == 0
    else:
        assert (results, verified) == ({"verify": 400, "resend": 200}, False)


# ---- resendEmailVerification ---------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_resend_issues_a_new_bearer_that_supersedes_the_old_one(browser, provider):
    browser.signup()
    _, first = link_of(provider.sent[0])
    response = browser.post("email/resend-verification")
    assert response.status_code == 200
    assert response["Cache-Control"] == NO_STORE
    body = response.json()
    assert set(body) == {"delivery"}
    assert body["delivery"]["purpose"] == "email_verification"
    assert body["delivery"]["status"] == "provider_accepted"
    assert EmailDelivery.objects.count() == 2
    _, second = link_of(provider.sent[1])
    assert second != first
    assert EmailVerificationBearer.objects.filter(superseded_at__isnull=True, consumed_at__isnull=True).get().digest == bearer_digest(second)

    assert verify(browser, first).json() == INVALID_VERIFIER
    assert verify(browser, second).status_code == 204


@pytest.mark.django_db(transaction=True)
def test_failed_delivery_is_recovered_by_a_rate_limited_resend(browser, provider):
    provider.outcome = ProviderRejected("no")
    assert browser.signup().json()["delivery"]["status"] == "failed"
    # The resend may fail too: reported honestly, the account keeps one usable bearer.
    provider.outcome = ProviderTimeout("slow")
    response = browser.post("email/resend-verification")
    assert (response.status_code, response.json()["delivery"]["status"]) == (200, "unknown")
    assert response.json()["delivery"]["provider_accepted_at"] is None
    assert EmailVerificationBearer.objects.filter(superseded_at__isnull=True, consumed_at__isnull=True).count() == 1
    assert_throttled(browser.post("email/resend-verification"))

    RateLimitBucket.objects.all().delete()  # the 2-minute window has passed
    provider.outcome = None
    response = browser.post("email/resend-verification")
    assert response.json()["delivery"]["status"] == "provider_accepted"
    [message] = provider.sent
    assert verify(browser, link_of(message)[1]).status_code == 204


@pytest.mark.django_db
def test_resend_for_a_verified_account_is_409_and_sends_nothing(make_user, browser):
    account(make_user)
    browser.login("member@example.com")
    response = browser.post("email/resend-verification")
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
    assert not EmailDelivery.objects.exists()
    assert not EmailVerificationBearer.objects.exists()


@pytest.mark.django_db
def test_resend_requires_a_session_and_csrf(make_user, browser):
    browser.csrf()
    assert browser.post("email/resend-verification").status_code == 401
    account(make_user, verified=False)
    browser.login("member@example.com")
    assert browser.post("email/resend-verification", csrf=False).status_code == 403
    assert not EmailDelivery.objects.exists()


@pytest.mark.django_db
def test_resend_is_limited_per_user(make_user, browser):
    account(make_user, verified=False)
    account(make_user, "second@example.com", verified=False)
    browser.login("member@example.com")
    assert browser.post("email/resend-verification").status_code == 200
    assert_throttled(browser.post("email/resend-verification"))
    other = Browser()
    other.login("second@example.com")
    assert other.post("email/resend-verification").status_code == 200


@pytest.mark.django_db
def test_resend_hourly_limit(make_user, browser):
    user = account(make_user, verified=False)
    browser.login("member@example.com")
    two_minutes = limiter.rates_for("resend_email_verification_user")[0]
    for _ in range(5):
        assert browser.post("email/resend-verification").status_code == 200
        # Only the 2-minute counter's window passes between attempts.
        RateLimitBucket.objects.filter(
            key=limiter.bucket_key("resend_email_verification_user", two_minutes, str(user.pk))
        ).delete()
    assert_throttled(browser.post("email/resend-verification"))


# ---- segregation of unverified accounts ----------------------------------------------------------


@pytest.mark.django_db
def test_restricted_session_reaches_only_the_verification_lifecycle(make_user, browser):
    account(make_user, verified=False)
    browser.login("member@example.com")
    assert browser.get("me").status_code == 200
    assert browser.post("email/resend-verification").status_code == 200
    browser.csrf()
    assert browser.post("email/verify", {"verifier": "unknown"}).status_code == 400  # reachable, not gated
    for response in (request_change(browser), verify_change(browser, "anything")):
        assert response.status_code == 403
        assert response.json() == FORBIDDEN
    assert protected_status(browser) == 403
    assert not PrimaryEmailChange.objects.exists()
    assert browser.post("logout").status_code == 204


def test_primary_email_change_views_keep_the_verification_gate():
    assert not views.RequestPrimaryEmailChangeView.allow_unverified
    assert not views.VerifyPrimaryEmailChangeView.allow_unverified


# ---- requestPrimaryEmailChange ------------------------------------------------------------------


@pytest.mark.django_db
def test_request_change_creates_a_pending_change_bound_to_this_session(make_user, browser, provider, django_capture_on_commit_callbacks):
    user = account(make_user)
    browser.login("member@example.com")
    response = committed(django_capture_on_commit_callbacks, lambda: request_change(browser, "  New.Address@Example.COM "))
    assert response.status_code == 202
    assert response["Cache-Control"] == NO_STORE
    body = response.json()
    assert set(body) == {"delivery"}
    assert body["delivery"]["purpose"] == "email_verification"

    change = PrimaryEmailChange.objects.get()
    assert (change.user_id, change.new_email) == (user.pk, "new.address@example.com")
    assert (change.expires_at - change.created_at).total_seconds() == pytest.approx(3600, abs=5)
    assert browser.session()[PRIMARY_EMAIL_CHANGE_SESSION_KEY] == str(change.pk)
    delivery = EmailDelivery.objects.get()
    assert (str(delivery.pk), delivery.template, delivery.subject_id) == (body["delivery"]["id"], "primary-email-change", change.pk)

    [message] = provider.sent
    assert message.to == "new.address@example.com"
    base, bearer = link_of(message)
    assert base == "http://testserver/verify-email-change" and "?" not in base
    assert len(bearer) >= 43 and change.digest == bearer_digest(bearer) != bearer
    # Until verification the current address stays in effect and the new one is not reserved.
    assert User.objects.get().email == "member@example.com"
    assert list(EmailAddress.objects.values_list("email", flat=True)) == ["member@example.com"]


@pytest.mark.django_db
def test_request_change_needs_recent_authentication(make_user, browser):
    account(make_user)
    browser.login("member@example.com")
    age_authentication(browser, settings.ACCOUNT_REAUTHENTICATION_TIMEOUT + 1)
    response = request_change(browser)
    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert not PrimaryEmailChange.objects.exists() and not EmailDelivery.objects.exists()
    browser.login("member@example.com")  # reauthenticating opens the window again
    assert request_change(browser).status_code == 202


@pytest.mark.django_db
def test_request_change_without_any_authentication_record_is_403(make_user, browser):
    account(make_user)
    browser.login("member@example.com")
    session = browser.client.session
    del session[AUTHENTICATION_METHODS_SESSION_KEY]
    session.save()
    assert request_change(browser).status_code == 403


@pytest.mark.django_db
def test_request_change_requires_a_session_and_csrf(make_user, browser):
    browser.csrf()
    assert request_change(browser).status_code == 401
    account(make_user)
    browser.login("member@example.com")
    assert browser.post("email/change", {"new_email": "x@example.com"}, csrf=False).status_code == 403
    assert not PrimaryEmailChange.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize("new_email", ["member@example.com", " MEMBER@example.com", "taken@example.com", "secondary@example.com", "unverified@example.com"])
def test_request_change_to_a_current_or_used_address_is_409(make_user, browser, new_email):
    account(make_user)
    holder = make_user("taken@example.com")
    EmailAddress.objects.create(user=holder, email="secondary@example.com", primary=False, verified=True)
    make_user("unverified@example.com", verified=False)
    browser.login("member@example.com")
    response = request_change(browser, new_email)
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
    assert not PrimaryEmailChange.objects.exists() and not EmailDelivery.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize("body, field", [({}, "new_email"), ({"new_email": "not-an-address"}, "new_email"), ({"new_email": 1}, "new_email"), ({"new_email": "a@example.com", "x": 1}, "x")])
def test_request_change_validation_errors_are_400(make_user, browser, body, field):
    account(make_user)
    browser.login("member@example.com")
    response = browser.post("email/change", body)
    assert response.status_code == 400
    assert field in response.json()["fields"]


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("outcome, status", [(ProviderRejected("no"), "failed"), (ProviderTimeout("slow"), "unknown")])
def test_request_change_survives_delivery_failure_and_can_be_requested_again(make_user, browser, provider, outcome, status):
    account(make_user)
    browser.login("member@example.com")
    provider.outcome = outcome
    response = request_change(browser)
    assert (response.status_code, response.json()["delivery"]["status"]) == (202, status)
    assert PrimaryEmailChange.objects.filter(superseded_at__isnull=True).count() == 1
    provider.outcome = None
    assert request_change(browser).json()["delivery"]["status"] == "provider_accepted"
    [message] = provider.sent
    assert verify_change(browser, link_of(message)[1]).status_code == 204


@pytest.mark.django_db
def test_a_new_request_supersedes_the_previous_change(make_user, browser, provider, django_capture_on_commit_callbacks):
    account(make_user)
    browser.login("member@example.com")
    committed(django_capture_on_commit_callbacks, lambda: request_change(browser, "first@example.com"))
    committed(django_capture_on_commit_callbacks, lambda: request_change(browser, "second@example.com"))
    first, second = (link_of(message)[1] for message in provider.sent)
    assert verify_change(browser, first).json() == NO_COMPATIBLE_CHANGE
    assert verify_change(browser, second).status_code == 204
    assert User.objects.get().email == "second@example.com"


@pytest.mark.django_db
def test_request_change_limits_per_user_and_per_requested_address(make_user):
    for name in ("one", "two", "three", "four"):
        account(make_user, f"{name}@example.com")
    one = Browser()
    one.login("one@example.com")
    for i in range(5):
        assert request_change(one, f"target{i}@example.com").status_code == 202
    assert_throttled(request_change(one, "target9@example.com"))

    for name in ("two", "three"):
        b = Browser()
        b.login(f"{name}@example.com")
        assert request_change(b, "contested@example.com").status_code == 202
    four = Browser()
    four.login("four@example.com")
    # "contested" has had two requests: a third is allowed, a fourth (any spelling) is not.
    assert request_change(four, "contested@example.com").status_code == 202
    assert_throttled(request_change(four, " Contested@Example.com"))


# ---- verifyPrimaryEmailChange -------------------------------------------------------------------


def start_change(browser, provider, capture, new_email="new.address@example.com"):
    response = committed(capture, lambda: request_change(browser, new_email))
    assert response.status_code == 202
    return link_of(provider.sent[-1])[1]


@pytest.mark.django_db
def test_verify_change_switches_the_primary_email_rotates_and_revokes(make_user, provider, django_capture_on_commit_callbacks):
    user = account(make_user)
    laptop, phone, tablet = Browser(), Browser(), Browser()
    for b in (phone, tablet, laptop):
        b.login("member@example.com")
    session = laptop.client.session
    intent = set_invitation_intent(session, uuid.uuid4(), 2)
    session.save()
    bearer = start_change(laptop, provider, django_capture_on_commit_callbacks)
    old_key, other_keys = laptop.session_key, {phone.session_key, tablet.session_key}

    response = verify_change(laptop, bearer)
    assert response.status_code == 204
    assert response.content == b""
    assert response["Cache-Control"] == NO_STORE
    assert response.cookies["sessionid"].value

    user.refresh_from_db()
    assert user.email == "new.address@example.com"
    assert list(EmailAddress.objects.filter(user=user).values_list("email", "primary", "verified")) == [
        ("new.address@example.com", True, True)
    ]
    assert PrimaryEmailChange.objects.get().consumed_at is not None
    # The current session was rotated and keeps its login and intent; every other session is gone.
    assert laptop.session_key not in (None, old_key)
    assert set(Session.objects.filter(user=user).values_list("session_key", flat=True)) == {laptop.session_key}
    assert not Session.objects.filter(session_key__in=other_keys | {old_key}).exists()
    session = laptop.session()
    assert session[SESSION_KEY] == str(user.pk)
    assert get_invitation_intent(session) == intent
    assert PRIMARY_EMAIL_CHANGE_SESSION_KEY not in session
    me = laptop.get("me").json()
    assert (me["email"], me["email_verified"]) == ("new.address@example.com", True)
    assert phone.get("me").status_code == 401 and tablet.get("me").status_code == 401
    # The old address no longer signs in; the new one does.
    assert Browser().login("member@example.com").status_code == 401
    assert Browser().login("new.address@example.com").status_code == 200


@pytest.mark.django_db
def test_verify_change_replay_is_409(make_user, browser, provider, django_capture_on_commit_callbacks):
    account(make_user)
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    assert verify_change(browser, bearer).status_code == 204
    replay = verify_change(browser, bearer)
    assert replay.status_code == 409
    assert replay.json() == NO_COMPATIBLE_CHANGE


@pytest.mark.django_db
def test_verify_change_needs_recent_authentication(make_user, browser, provider, django_capture_on_commit_callbacks):
    account(make_user)
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    age_authentication(browser, settings.ACCOUNT_REAUTHENTICATION_TIMEOUT + 1)
    response = verify_change(browser, bearer)
    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert User.objects.get().email == "member@example.com"
    assert PrimaryEmailChange.objects.get().consumed_at is None


@pytest.mark.django_db
def test_verify_change_from_another_session_of_the_same_account_is_409(make_user, provider, django_capture_on_commit_callbacks):
    account(make_user)
    requester, other = Browser(), Browser()
    requester.login("member@example.com")
    other.login("member@example.com")  # recently authenticated too, but not the requesting session
    bearer = start_change(requester, provider, django_capture_on_commit_callbacks)
    assert verify_change(other, bearer).json() == NO_COMPATIBLE_CHANGE
    # A new login in the requesting browser is a new session as well.
    requester.login("member@example.com")
    assert verify_change(requester, bearer).json() == NO_COMPATIBLE_CHANGE
    assert User.objects.get().email == "member@example.com"
    assert PrimaryEmailChange.objects.get().consumed_at is None


@pytest.mark.django_db
@pytest.mark.parametrize("state", ["unknown", "expired", "superseded", "other-account", "initial-verification"])
def test_every_unusable_change_bearer_gets_the_same_409(make_user, browser, provider, django_capture_on_commit_callbacks, state):
    user = account(make_user)
    stranger = account(make_user, "stranger@example.com")
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    change = PrimaryEmailChange.objects.get()
    if state == "unknown":
        bearer = "never-issued"
    elif state == "expired":
        PrimaryEmailChange.objects.update(expires_at=timezone.now() - datetime.timedelta(seconds=1))
    elif state == "superseded":
        PrimaryEmailChange.objects.update(superseded_at=timezone.now())
    elif state == "other-account":
        PrimaryEmailChange.objects.update(user=stranger)
    elif state == "initial-verification":
        bearer = issue_bearer(user, email="new.address@example.com")
    response = verify_change(browser, bearer)
    assert response.status_code == 409
    assert response.json() == NO_COMPATIBLE_CHANGE
    assert User.objects.get(pk=user.pk).email == "member@example.com"
    assert PrimaryEmailChange.objects.get(pk=change.pk).consumed_at is None


@pytest.mark.django_db
def test_verify_change_to_an_address_taken_meanwhile_is_409(make_user, browser, provider, django_capture_on_commit_callbacks):
    account(make_user)
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    make_user("new.address@example.com", verified=False)  # someone signed up with it meanwhile
    assert verify_change(browser, bearer).json() == NO_COMPATIBLE_CHANGE
    assert User.objects.filter(email="member@example.com").exists()
    assert PrimaryEmailChange.objects.get().consumed_at is None


@pytest.mark.django_db
def test_verify_change_losing_the_race_on_the_unique_index_is_409(make_user, browser, provider, django_capture_on_commit_callbacks):
    account(make_user)
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    make_user("new.address@example.com")
    # The address check ran before the competitor committed: the unique index still refuses the write.
    with mock.patch("apps.accounts.email_change._address_taken", return_value=False):
        assert verify_change(browser, bearer).json() == NO_COMPATIBLE_CHANGE
    assert User.objects.filter(email="member@example.com").exists()
    assert PrimaryEmailChange.objects.get().consumed_at is None


@pytest.mark.django_db
@pytest.mark.parametrize("records", [None, "not-a-list", [], ["not-a-dict"], [{"method": "password"}], [{"at": "now"}], [{"at": True}]])
def test_malformed_authentication_records_never_count_as_recent(make_user, browser, records):
    account(make_user)
    browser.login("member@example.com")
    session = browser.client.session
    session[AUTHENTICATION_METHODS_SESSION_KEY] = records
    session.save()
    assert request_change(browser).status_code == 403


@pytest.mark.django_db
def test_verify_change_requires_a_session_and_csrf(make_user, browser, provider, django_capture_on_commit_callbacks):
    anonymous = Browser()
    anonymous.csrf()
    assert verify_change(anonymous, "anything").status_code == 401
    account(make_user)
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    assert browser.post("email/change/verify", {"verifier": bearer}, csrf=False).status_code == 403
    assert PrimaryEmailChange.objects.get().consumed_at is None


@pytest.mark.django_db
@pytest.mark.parametrize("body, field", [({}, "verifier"), ({"verifier": None}, "verifier"), ({"verifier": "x", "y": 1}, "y")])
def test_verify_change_validation_errors_are_400(make_user, browser, body, field):
    account(make_user)
    browser.login("member@example.com")
    response = browser.post("email/change/verify", body)
    assert response.status_code == 400
    assert field in response.json()["fields"]


@pytest.mark.django_db
def test_verify_change_is_limited_per_user(make_user, browser, provider, django_capture_on_commit_callbacks):
    account(make_user)
    browser.login("member@example.com")
    bearer = start_change(browser, provider, django_capture_on_commit_callbacks)
    for _ in range(10):
        assert verify_change(browser, "guess").status_code == 409
    assert_throttled(verify_change(browser, bearer))
    assert PrimaryEmailChange.objects.get().consumed_at is None


@pytest.mark.django_db
def test_revocation_failure_rolls_the_whole_change_back(make_user, provider, django_capture_on_commit_callbacks):
    account(make_user)
    laptop, phone = Browser(), Browser()
    laptop.login("member@example.com")
    phone.login("member@example.com")
    bearer = start_change(laptop, provider, django_capture_on_commit_callbacks)
    with mock.patch("apps.accounts.sessions.revoke_other_sessions", side_effect=DatabaseError("down")):
        with pytest.raises(DatabaseError):
            verify_change(laptop, bearer)
    assert User.objects.get().email == "member@example.com"
    assert EmailAddress.objects.get().email == "member@example.com"
    assert PrimaryEmailChange.objects.get().consumed_at is None
    assert phone.get("me").status_code == 200


@pytest.mark.django_db(transaction=True)
def test_concurrent_change_and_signup_for_one_address_leave_one_owner(make_user, provider):
    account(make_user)
    browser = Browser()
    browser.login("member@example.com")
    assert request_change(browser, "contested@example.com").status_code == 202
    bearer = link_of(provider.sent[-1])[1]
    newcomer = Browser(remote_addr="198.51.100.20")
    newcomer.csrf()
    barrier = threading.Barrier(2)
    results = {}

    def run(name, call):
        try:
            barrier.wait(timeout=10)
            results[name] = call().status_code
        finally:
            connection.close()

    threads = [
        threading.Thread(target=run, args=("change", lambda: verify_change(browser, bearer))),
        threading.Thread(target=run, args=("signup", lambda: newcomer.signup(email="contested@example.com"))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive(), "deadlock"
    assert sorted(results.values()) in ([201, 409], [204, 409])
    assert User.objects.filter(email="contested@example.com").count() == 1
    assert EmailAddress.objects.filter(email="contested@example.com").count() == 1


@pytest.mark.django_db(transaction=True)
def test_concurrent_verifications_of_one_change_complete_it_once(make_user, provider):
    account(make_user)
    browser = Browser()
    browser.login("member@example.com")
    assert request_change(browser).status_code == 202
    bearer = link_of(provider.sent[-1])[1]
    barrier = threading.Barrier(3)
    statuses = []

    def run():
        try:
            barrier.wait(timeout=10)
            statuses.append(verify_change(browser, bearer).status_code)
        finally:
            connection.close()

    threads = [threading.Thread(target=run) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(statuses) == [204, 409, 409]
    assert User.objects.get().email == "new.address@example.com"
    assert PrimaryEmailChange.objects.get().consumed_at is not None


# ---- bearers never persisted, logged or echoed --------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_no_lifecycle_bearer_reaches_persistence_logs_or_responses(make_user, provider, caplog):
    caplog.set_level(logging.DEBUG)
    unverified = Browser()
    unverified.signup(email="private.person@example.com")
    unverified.post("email/resend-verification")
    verification_bearers = [link_of(m)[1] for m in provider.sent]
    responses = [verify(unverified, verification_bearers[0]), verify(unverified, verification_bearers[1])]

    account(make_user, "member@example.com")
    changer = Browser()
    changer.login("member@example.com")
    responses.append(request_change(changer, "secret.new@example.com"))
    change_bearer = link_of(provider.sent[-1])[1]
    responses += [verify_change(changer, "wrong"), verify_change(changer, change_bearer)]

    persisted = "".join(
        repr(list(model.objects.values()))
        for model in (EmailVerificationBearer, PrimaryEmailChange, EmailDelivery, RateLimitBucket, Session)
    )
    for secret in (*verification_bearers, change_bearer):
        for haystack in (persisted, caplog.text, *(r.content.decode() for r in responses)):
            assert secret not in haystack
    deliveries = repr(list(EmailDelivery.objects.values()))
    assert "private.person" not in deliveries and "secret.new" not in deliveries
    assert "verify-email" not in deliveries


# ---- ADR-016 constants ---------------------------------------------------------------------------


def test_lifecycle_constants_match_adr_016():
    assert settings.AUTH_EMAIL_VERIFICATION_LIFETIME_SECONDS == 24 * 3600
    assert settings.AUTH_PRIMARY_EMAIL_CHANGE_LIFETIME_SECONDS == 3600
    assert settings.ACCOUNT_REAUTHENTICATION_TIMEOUT == 5 * 60
    limits = settings.AUTH_RATE_LIMITS
    assert limits["verify_email_ip"] == (("ip", 20, 300),)
    assert limits["resend_email_verification_user"] == (("user", 1, 120), ("user", 5, 3600))
    assert limits["email_change_user"] == (("user", 5, 3600),)
    assert limits["email_change_email"] == (("email", 3, 3600),)
    assert limits["verify_email_change_user"] == (("user", 10, 300),)


@pytest.mark.django_db
def test_social_only_account_is_not_exempt_from_recent_reauthentication(make_user, browser):
    """allauth's own check waives reauthentication for passwordless accounts; this one never does."""
    account(make_user)
    browser.login("member@example.com")
    age_authentication(browser, settings.ACCOUNT_REAUTHENTICATION_TIMEOUT + 1)
    User.objects.update(password="!unusable")
    session = browser.client.session
    session["_auth_user_hash"] = User.objects.get().get_session_auth_hash()
    session.save()
    assert request_change(browser).status_code == 403

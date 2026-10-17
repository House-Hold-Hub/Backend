"""Racing password-recovery requests on real concurrent PostgreSQL transactions (Backend#36).

Each worker uses its own connection and its own browser, so the transactions really interleave.
"""

import threading
import time
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.db import transaction

from apps.accounts.models import PasswordResetBearer
from apps.accounts.password_recovery import reset_password
from apps.accounts.sessions import SessionStore
from apps.accounts.test_auth_api import PASSWORD, Browser, account
from apps.accounts.test_password_recovery import change, forgot, mailed_bearer, reset, reset_bearer, sessions_of
from apps.accounts.test_session_concurrency import BLOCKED, Worker, authenticated_session, hold_rotation
from apps.accounts.verification import bearer_digest
from apps.email_delivery import service
from apps.email_delivery.testing import RecordingProvider

User = get_user_model()
pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    provider = RecordingProvider()
    monkeypatch.setattr(service, "get_provider", lambda: provider)
    return provider


@pytest.fixture(autouse=True)
def no_response_floor(settings):
    settings.AUTH_PASSWORD_RESET_MIN_RESPONSE_SECONDS = 0


def race(calls):
    """Run the callables at once, each on its own connection; returns their results in order."""
    barrier = threading.Barrier(len(calls))

    def gated(call):
        def run():
            barrier.wait(timeout=10)
            return call()

        return run

    workers = [Worker(gated(call)) for call in calls]
    for worker in workers:
        worker.start()
    return [worker.finish() for worker in workers]


def prepared(path_browser=None):
    browser = path_browser or Browser()
    browser.csrf()
    return browser


def test_concurrent_resets_with_one_bearer_succeed_exactly_once(make_user):
    user = account(make_user)
    bearer = reset_bearer(user)
    passwords = [f"racing passphrase number {i}" for i in range(6)]
    browsers = [prepared() for _ in passwords]

    statuses = race([lambda b=b, p=p: reset(b, bearer, p).status_code for b, p in zip(browsers, passwords, strict=True)])

    assert sorted(statuses) == [204] + [400] * 5
    winner = passwords[statuses.index(204)]
    stored = User.objects.get(pk=user.pk)
    assert stored.check_password(winner)
    assert not any(stored.check_password(p) for p in passwords if p != winner)
    assert PasswordResetBearer.objects.get().consumed_at is not None
    assert sessions_of(user) == set()


def test_concurrent_requests_leave_exactly_one_usable_bearer(make_user, provider, settings):
    account(make_user)
    settings.AUTH_RATE_LIMITS = {**settings.AUTH_RATE_LIMITS, "password_reset_email": (("email", 100, 3600),)}
    browsers = [prepared() for _ in range(5)]

    statuses = race([lambda b=b: forgot(b).status_code for b in browsers])

    assert statuses == [202] * 5
    assert PasswordResetBearer.objects.count() == 5
    assert PasswordResetBearer.objects.filter(superseded_at__isnull=True, consumed_at__isnull=True).count() == 1
    mailed = [mailed_bearer(provider, i) for i in range(5)]
    assert sorted(reset(Browser(), bearer, "a fresh long passphrase!").status_code for bearer in mailed) == [204] + [400] * 4


def test_a_reset_waits_for_a_rotation_in_flight_and_removes_the_rotated_session_too(make_user):
    user = account(make_user)
    bearer = reset_bearer(user)
    old_key = authenticated_session(user)
    rotated, release = threading.Event(), threading.Event()
    rotation = Worker(hold_rotation(old_key, rotated, release))
    rotation.start()
    assert rotated.wait(10)

    resetting = Worker(lambda: reset_password(SimpleNamespace(), bearer, "a fresh long passphrase!"))
    resetting.start()
    time.sleep(BLOCKED)
    assert resetting.is_alive(), "the reset must wait for the rotation holding the account lock"
    release.set()
    new_key = rotation.finish()
    resetting.finish()

    assert new_key != old_key
    assert sessions_of(user) == set()
    assert User.objects.get(pk=user.pk).check_password("a fresh long passphrase!")


def test_a_session_saved_while_the_reset_holds_the_account_lock_is_inert_afterwards(make_user):
    user = account(make_user)
    bearer = reset_bearer(user)
    stale_hash = user.get_session_auth_hash()
    locked, release = threading.Event(), threading.Event()

    def slow_reset():
        with transaction.atomic():
            reset_password(SimpleNamespace(), bearer, "a fresh long passphrase!")
            locked.set()
            assert release.wait(10)

    resetting = Worker(slow_reset)
    resetting.start()
    assert locked.wait(10)

    def late_login():
        store = SessionStore()
        store.update({"_auth_user_id": str(user.pk), "_auth_user_backend": "django.contrib.auth.backends.ModelBackend", "_auth_user_hash": stale_hash})
        store.create()  # waits for the account lock the reset holds
        return store.session_key

    creating = Worker(late_login)
    creating.start()
    time.sleep(BLOCKED)
    assert creating.is_alive(), "a session for the account must wait for the reset"
    release.set()
    resetting.finish()
    late_key = creating.finish()

    # The row exists (written after the revocation) but carries the old authentication hash.
    client = Browser()
    client.client.cookies["sessionid"] = late_key
    assert client.get("me").status_code == 401


def test_concurrent_changes_with_one_current_password_succeed_exactly_once(make_user):
    user = account(make_user)
    passwords = [f"racing passphrase number {i}" for i in range(5)]
    browsers = [Browser() for _ in passwords]
    for browser in browsers:
        assert browser.login(user.email).status_code == 200

    statuses = race([lambda b=b, p=p: change(b, PASSWORD, p).status_code for b, p in zip(browsers, passwords, strict=True)])

    assert statuses.count(204) == 1
    assert set(statuses) <= {204, 400, 401}  # a loser is refused as stale, or already revoked by the winner
    winner = passwords[statuses.index(204)]
    stored = User.objects.get(pk=user.pk)
    assert stored.check_password(winner)
    assert len(sessions_of(user)) == 1  # the winner's rotated session only


def test_a_reset_racing_a_change_ends_in_one_consistent_state(make_user):
    """Whichever commits first decides: a change voids the reset link; a reset revokes the changer's session."""
    outcomes = set()
    for attempt in range(4):
        user = account(make_user, f"racer{attempt}@example.com")
        bearer = reset_bearer(user)
        changer = Browser()
        assert changer.login(user.email).status_code == 200
        resetter = prepared()

        reset_status, change_status = race(
            [
                lambda r=resetter, b=bearer: reset(r, b, "the reset passphrase!!").status_code,
                lambda c=changer: change(c, PASSWORD, "the change passphrase!").status_code,
            ]
        )

        stored = User.objects.get(pk=user.pk)
        if reset_status == 204:
            outcomes.add("reset")
            assert change_status in {204, 400, 401}
            assert stored.check_password("the reset passphrase!!")
            assert sessions_of(user) == set()
        else:
            outcomes.add("change")
            assert (reset_status, change_status) == (400, 204)
            assert stored.check_password("the change passphrase!")
            assert len(sessions_of(user)) == 1
    assert outcomes <= {"reset", "change"}


def test_a_bearer_digest_is_never_accepted_as_the_bearer(make_user):
    user = account(make_user)
    bearer = reset_bearer(user)
    assert reset(prepared(), bearer_digest(bearer)).status_code == 400
    assert not PasswordResetBearer.objects.get().consumed_at

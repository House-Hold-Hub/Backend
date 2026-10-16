"""Revocation racing rotation and in-flight requests, on real concurrent PostgreSQL transactions.

Each worker thread uses its own database connection, so these tests commit (``transactional_db``)
and interleave transactions for real rather than simulating them.
"""

import threading
import time

import pytest
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, get_user_model
from django.contrib.sessions.backends.base import UpdateError
from django.db import connection, transaction
from django.http import JsonResponse
from django.test import Client
from django.urls import path

from apps.accounts.models import Session
from apps.accounts.sessions import SessionStore, revoke_all_sessions, rotate_and_revoke_others

User = get_user_model()

pytestmark = pytest.mark.django_db(transaction=True)

BLOCKED = 0.5  # how long a worker must stay blocked to count as waiting on a lock


def authenticated_session(user):
    store = SessionStore()
    store.update({SESSION_KEY: str(user.pk), BACKEND_SESSION_KEY: settings.AUTHENTICATION_BACKENDS[0]})
    store[HASH_SESSION_KEY] = user.get_session_auth_hash()
    store.create()
    return store.session_key


class Worker(threading.Thread):
    """Runs ``target`` on its own connection and keeps its result or exception."""

    def __init__(self, target):
        super().__init__(daemon=True)
        self.target = target
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.target()
        except BaseException as exc:  # surfaced by finish()
            self.error = exc
        finally:
            connection.close()

    def finish(self):
        self.join(timeout=10)
        assert not self.is_alive(), "worker deadlocked"
        if self.error:
            raise self.error
        return self.result


def hold_rotation(session_key, rotated, release):
    """Rotate ``session_key`` and keep the transaction (and its new row) open until ``release``."""

    def run():
        with transaction.atomic():
            store = SessionStore(session_key)
            store.cycle_key()
            rotated.set()
            assert release.wait(10)
            return store.session_key

    return run


def owned(user):
    return set(Session.objects.filter(user=user).values_list("session_key", flat=True))


@pytest.mark.parametrize("revoke", ["revoke_all_sessions", "disable"])
def test_revocation_waits_for_an_in_flight_rotation_and_then_removes_its_new_key(make_user, revoke):
    user = make_user()
    old_key = authenticated_session(user)
    rotated, release = threading.Event(), threading.Event()
    rotation = Worker(hold_rotation(old_key, rotated, release))
    rotation.start()
    assert rotated.wait(10)

    def revocation():
        if revoke == "disable":
            User.objects.filter(pk=user.pk).update(is_active=False)  # the database trigger
        else:
            revoke_all_sessions(User.objects.get(pk=user.pk))

    revoking = Worker(revocation)
    revoking.start()
    time.sleep(BLOCKED)
    assert revoking.is_alive(), "revocation must wait for the rotation holding the account lock"
    release.set()
    new_key = rotation.finish()
    revoking.finish()

    assert new_key != old_key
    assert owned(user) == set()  # neither the old key nor the rotated one survives


def test_rotation_that_waited_for_a_revocation_does_not_resurrect_the_session(make_user):
    user = make_user()
    session_key = authenticated_session(user)
    stale = SessionStore(session_key)
    assert SESSION_KEY in stale  # a request that loaded the session before it was revoked

    locked, release = threading.Event(), threading.Event()

    def revocation():
        with transaction.atomic():
            revoke_all_sessions(User.objects.get(pk=user.pk))
            locked.set()
            assert release.wait(10)

    revoking = Worker(revocation)
    revoking.start()
    assert locked.wait(10)
    def rotation():
        stale.cycle_key()
        return stale.session_key, dict(stale.items())

    rotating = Worker(rotation)
    rotating.start()
    time.sleep(BLOCKED)
    assert rotating.is_alive(), "rotation must wait for the revocation holding the account lock"
    release.set()
    revoking.finish()
    new_key, data = rotating.finish()

    assert data == {}  # nothing of the revoked session is carried into the new key
    assert owned(user) == set()
    assert Session.objects.get(session_key=new_key).user_id is None


def test_a_request_that_loaded_a_revoked_session_cannot_write_it_back(make_user):
    user = make_user()
    stale = SessionStore(authenticated_session(user))
    assert SESSION_KEY in stale  # loaded before the revocation
    revoke_all_sessions(user)
    stale["late"] = "write"
    with pytest.raises(UpdateError):
        stale.save()
    assert owned(user) == set()


def revoke_then_write(request):
    revoke_all_sessions(request.user)  # as if another request revoked it meanwhile
    request.session["late"] = "write"
    return JsonResponse({})


urlpatterns = [path("revoke-then-write", revoke_then_write)]


@pytest.mark.urls(__name__)
def test_an_in_flight_request_on_a_revoked_session_is_interrupted(make_user):
    user = make_user()
    browser = Client(raise_request_exception=False)
    browser.force_login(user)
    # Django answers SessionInterrupted (400) instead of saving the deleted session.
    assert browser.get("/revoke-then-write").status_code == 400
    assert owned(user) == set()


def test_concurrent_identity_rotations_leave_at_most_the_current_sessions(make_user, rf):
    """Two browsers change identity data at once: each revokes the other, neither keeps a stale key."""
    user = make_user()
    keys = [authenticated_session(user) for _ in range(2)]
    barrier = threading.Barrier(2)

    def change(session_key):
        def run():
            request = rf.post("/")
            request.session = SessionStore(session_key)
            request.user = User.objects.get(pk=user.pk)
            barrier.wait(5)
            rotate_and_revoke_others(request, request.user)
            return request.session.session_key

        return run

    workers = [Worker(change(k)) for k in keys]
    for worker in workers:
        worker.start()
    results = [worker.finish() for worker in workers]

    survivors = owned(user)
    assert not set(keys) & survivors  # both old keys are gone
    assert len(survivors) <= 1  # the later change revoked the earlier one's rotated session
    assert survivors <= set(results)

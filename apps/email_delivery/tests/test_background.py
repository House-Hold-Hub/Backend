"""Post-response submissions (``DeferredSubmissions.run_in_background``): bounded, no queue, clean lifecycle (ADR-015).

These commit for real: the submission runs on another thread with its own database connection.
"""

import threading

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction

from apps.email_delivery import service
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.service import DeferredSubmissions, queue_email

pytestmark = pytest.mark.django_db(transaction=True)
Status = EmailDelivery.Status


@pytest.fixture(autouse=True)
def _drained():
    yield
    service.join_background_submissions()
    assert service._background_threads == []


def queue_batch(message, count=1):
    deferred = DeferredSubmissions()
    with transaction.atomic():
        deliveries = [queue_email(message, template="password-reset", defer=deferred) for _ in range(count)]
    return deferred, [d.pk for d in deliveries]


def statuses(ids):
    return sorted((d.status, d.error_class) for d in EmailDelivery.objects.filter(pk__in=ids))


def test_concurrency_is_bounded_and_overflow_is_recorded_not_queued(message, use_provider, settings):
    settings.EMAIL_DELIVERY = {**settings.EMAIL_DELIVERY, "MAX_BACKGROUND_SUBMISSIONS": 2}
    arrived, release = threading.Semaphore(0), threading.Event()

    def block(_message):
        arrived.release()
        assert release.wait(10)

    provider = use_provider(block)
    started = []
    for _ in range(2):
        deferred, ids = queue_batch(message)
        deferred.run_in_background()
        started += ids
        assert arrived.acquire(timeout=10)  # this one is now inside the provider call

    overflow = []
    for _ in range(5):  # a burst while every slot is busy
        deferred, ids = queue_batch(message)
        deferred.run_in_background()
        overflow += ids
    assert len(service._background_threads) == 2
    assert statuses(overflow) == [(Status.FAILED, "not_submitted")] * 5  # settled at once, nothing was sent
    assert not arrived.acquire(blocking=False) and len(provider.calls) == 2

    release.set()
    service.join_background_submissions()
    assert statuses(started) == [(Status.ACCEPTED, "")] * 2
    assert len(provider.sent) == 2

    deferred, ids = queue_batch(message)  # the slots are free again
    deferred.run_in_background()
    service.join_background_submissions()
    assert statuses(ids) == [(Status.ACCEPTED, "")]


def test_the_thread_is_not_a_daemon_and_closes_its_connection(message, use_provider):
    seen: dict = {}

    def inspect(_message):
        thread = threading.current_thread()
        seen.update(daemon=thread.daemon, name=thread.name, raw=connection.connection)

    use_provider(inspect)
    deferred, ids = queue_batch(message)
    deferred.run_in_background()
    service.join_background_submissions()
    assert seen["daemon"] is False and seen["name"] == "deferred-email-submission"
    assert seen["raw"] is not None and seen["raw"].closed  # not left open for a thread that no longer exists
    assert statuses(ids) == [(Status.ACCEPTED, "")]


def test_an_interrupted_call_leaves_an_honest_state_and_frees_its_slot(message, use_provider):
    use_provider(SystemExit())
    deferred, ids = queue_batch(message)
    deferred.run_in_background()
    service.join_background_submissions()
    assert statuses(ids) == [(Status.UNKNOWN, "interrupted")]  # the provider may have accepted it


def test_a_thread_that_cannot_start_settles_the_deliveries_without_raising(message, use_provider, monkeypatch):
    provider = use_provider()

    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    deferred, ids = queue_batch(message, 2)
    deferred.run_in_background()
    assert service._background_threads == []
    assert statuses(ids) == [(Status.FAILED, "not_submitted")] * 2
    assert provider.sent == []


def test_overflow_never_overwrites_a_delivery_that_was_already_claimed(message, use_provider, settings):
    settings.EMAIL_DELIVERY = {**settings.EMAIL_DELIVERY, "MAX_BACKGROUND_SUBMISSIONS": 1}
    use_provider()
    deferred, ids = queue_batch(message)
    EmailDelivery.objects.filter(pk__in=ids).update(status=Status.ACCEPTED)
    with service._background_lock:
        service._background_threads.append(threading.current_thread())  # occupy the only slot
    try:
        deferred.run_in_background()
    finally:
        with service._background_lock:
            service._background_threads.remove(threading.current_thread())
    assert statuses(ids) == [(Status.ACCEPTED, "")]


def test_one_failing_submission_does_not_skip_the_next(message, use_provider, monkeypatch):
    provider = use_provider()
    real = service._submit
    calls = []

    def flaky(delivery_id, msg):
        calls.append(delivery_id)
        if len(calls) == 1:
            raise RuntimeError(f"boom {msg.to}")
        return real(delivery_id, msg)

    monkeypatch.setattr(service, "_submit", flaky)
    deferred, ids = queue_batch(message, 2)
    deferred.run_in_background()
    service.join_background_submissions()
    assert len(calls) == 2 and len(provider.sent) == 1


def test_the_logs_of_a_failure_carry_no_recipient(message, use_provider, monkeypatch, caplog):
    monkeypatch.setattr(service, "_submit", lambda *a: (_ for _ in ()).throw(RuntimeError(f"boom {a[1].to}")))
    deferred, _ids = queue_batch(message)
    deferred.run_in_background()
    service.join_background_submissions()
    assert "submission failed unexpectedly" in caplog.text and message.to not in caplog.text


@pytest.mark.parametrize("value", [0, -1, True, "4", 2.5, None])
def test_the_concurrency_bound_must_be_a_positive_integer(value, settings):
    settings.EMAIL_DELIVERY = {**settings.EMAIL_DELIVERY, "MAX_BACKGROUND_SUBMISSIONS": value}
    with pytest.raises(ImproperlyConfigured):
        service.delivery_settings()

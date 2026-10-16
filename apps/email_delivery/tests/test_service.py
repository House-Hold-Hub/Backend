"""ADR-015 sequence, failure handling and recoverable states, with provider test doubles."""

import datetime
import uuid
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import DatabaseError, transaction
from django.utils import timezone

from apps.email_delivery import service
from apps.email_delivery.adapter import (
    ProviderNotConfigured,
    ProviderReceipt,
    ProviderRejected,
    ProviderTimeout,
    ProviderUnavailable,
)
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.service import EmailDeliveryError, queue_email

Status = EmailDelivery.Status
User = get_user_model()


def send(message, capture, **kwargs):
    """Queue inside a domain transaction and run the post-commit callbacks, as a request would."""
    with capture(execute=True):
        with transaction.atomic():
            delivery = queue_email(message, template="email-verification", **kwargs)
    delivery.refresh_from_db()
    return delivery


def test_provider_is_called_only_after_commit(message, use_provider, django_capture_on_commit_callbacks):
    provider = use_provider()
    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        with transaction.atomic():
            delivery = queue_email(message, template="email-verification")
            assert provider.sent == []
            assert EmailDelivery.objects.get(pk=delivery.pk).status == Status.PENDING
    assert len(callbacks) == 1
    assert provider.sent == [message]


def test_successful_submission_records_acceptance_not_delivery(
    message, use_provider, django_capture_on_commit_callbacks, settings
):
    provider = use_provider(request_id="req-abc.123")
    subject_id = uuid.uuid4()
    delivery = send(message, django_capture_on_commit_callbacks, subject_type="invitation", subject_id=subject_id)

    assert delivery.status == Status.ACCEPTED
    assert delivery.attempt_count == 1
    assert delivery.provider_request_id == "req-abc.123"
    assert delivery.error_class == ""
    assert delivery.last_attempt_at and delivery.completed_at
    assert (delivery.subject_type, delivery.subject_id) == ("invitation", subject_id)
    assert provider.calls == [{"idempotency_key": str(delivery.pk), "timeout": settings.EMAIL_DELIVERY["TIMEOUT_SECONDS"]}]
    # Acceptance is the strongest claim made: there is no inbox-delivery status and accepted is not "recoverable".
    assert "delivered" not in {value for value, _ in Status.choices}
    assert not delivery.is_recoverable


def test_rollback_discards_delivery_and_never_submits(message, use_provider, django_capture_on_commit_callbacks):
    provider = use_provider()
    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        with pytest.raises(RuntimeError):
            with transaction.atomic():
                User.objects.create_user(email="rolled.back@example.test", name="Rolled Back")
                queue_email(message, template="email-verification")
                raise RuntimeError("domain failure")
    assert callbacks == []
    assert provider.sent == []
    assert EmailDelivery.objects.count() == 0
    assert not User.objects.filter(email="rolled.back@example.test").exists()


@pytest.mark.django_db(transaction=True)
def test_queueing_outside_a_transaction_is_refused(message):
    with pytest.raises(EmailDeliveryError):
        queue_email(message, template="email-verification")
    assert EmailDelivery.objects.count() == 0


@pytest.mark.parametrize(
    ("error", "status", "error_class"),
    [
        (ProviderUnavailable("503 from https://x"), Status.FAILED, "unavailable"),
        (ProviderRejected("bad recipient"), Status.FAILED, "rejected"),
        (ProviderNotConfigured(), Status.FAILED, "not_configured"),
        (ProviderTimeout("slow"), Status.UNKNOWN, "timeout"),
        (RuntimeError("boom"), Status.UNKNOWN, "unexpected"),
        (ConnectionResetError("reset"), Status.UNKNOWN, "unexpected"),
    ],
)
def test_provider_exception_keeps_committed_domain_state_and_is_recoverable(
    message, use_provider, django_capture_on_commit_callbacks, error, status, error_class
):
    use_provider(error)
    with django_capture_on_commit_callbacks(execute=True):
        with transaction.atomic():
            user = User.objects.create_user(email="new.member@example.test", name="New Member")
            delivery = queue_email(message, template="email-verification", subject_type="user", subject_id=user.pk)
    # No exception escaped the callback and the domain row is committed.
    assert User.objects.filter(pk=user.pk).exists()
    delivery.refresh_from_db()
    assert (delivery.status, delivery.error_class) == (status, error_class)
    assert delivery.provider_request_id == ""
    assert delivery.is_recoverable


def test_default_provider_records_not_configured_instead_of_succeeding(message, django_capture_on_commit_callbacks):
    delivery = send(message, django_capture_on_commit_callbacks)
    assert (delivery.status, delivery.error_class) == (Status.FAILED, "not_configured")


def test_timeout_is_bounded_by_setting_and_reported_as_unknown(
    message, use_provider, django_capture_on_commit_callbacks, settings
):
    settings.EMAIL_DELIVERY = {**settings.EMAIL_DELIVERY, "TIMEOUT_SECONDS": 2.5}
    provider = use_provider(latency=10)
    delivery = send(message, django_capture_on_commit_callbacks)
    assert provider.calls[0]["timeout"] == 2.5
    assert provider.sent == []
    assert (delivery.status, delivery.error_class) == (Status.UNKNOWN, "timeout")


@pytest.mark.parametrize(
    "override",
    [{"TIMEOUT_SECONDS": 0}, {"TIMEOUT_SECONDS": -1}, {"TIMEOUT_SECONDS": 31}, {"STALE_AFTER_SECONDS": 5}],
)
def test_unbounded_or_inconsistent_timeouts_are_rejected(override, settings):
    settings.EMAIL_DELIVERY = {**settings.EMAIL_DELIVERY, **override}
    with pytest.raises(ImproperlyConfigured):
        service.delivery_settings()


def test_interrupted_callback_is_recorded_unknown_and_not_swallowed(
    message, use_provider, django_capture_on_commit_callbacks
):
    use_provider(KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        with django_capture_on_commit_callbacks(execute=True):
            with transaction.atomic():
                delivery = queue_email(message, template="email-verification")
    delivery.refresh_from_db()
    assert (delivery.status, delivery.error_class) == (Status.UNKNOWN, "interrupted")


def test_failure_to_persist_the_outcome_never_reports_success(message, use_provider, django_capture_on_commit_callbacks):
    use_provider()
    with mock.patch.object(service, "_record_outcome", side_effect=DatabaseError):
        delivery = send(message, django_capture_on_commit_callbacks)
    assert delivery.status == Status.SUBMITTING  # settled to unknown by the reconciler, never "accepted"


def test_failure_to_claim_does_not_submit(message, use_provider, django_capture_on_commit_callbacks):
    provider = use_provider()
    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        with transaction.atomic():
            delivery = queue_email(message, template="email-verification")
    with mock.patch("django.db.models.query.QuerySet.update", side_effect=DatabaseError):
        callbacks[0]()
    delivery.refresh_from_db()
    assert provider.sent == []
    assert delivery.status == Status.PENDING


def test_a_delivery_is_never_submitted_twice(message, use_provider, django_capture_on_commit_callbacks):
    provider = use_provider()
    delivery = send(message, django_capture_on_commit_callbacks)
    service._submit(delivery.pk, message)
    assert len(provider.sent) == 1


def test_a_non_receipt_result_is_not_treated_as_acceptance(message, use_provider, django_capture_on_commit_callbacks):
    class Sloppy:
        def send(self, message, *, idempotency_key, timeout):
            return None

    use_provider(provider=Sloppy())
    delivery = send(message, django_capture_on_commit_callbacks)
    assert (delivery.status, delivery.error_class) == (Status.UNKNOWN, "unexpected")


@pytest.mark.parametrize(
    ("request_id", "stored"),
    [("req_1:abc-2", "req_1:abc-2"), ("has space", ""), ("https://x/?t=secret", ""), ("a" * 129, ""), ("", "")],
)
def test_provider_request_id_is_stored_only_when_it_is_a_plain_token(request_id, stored):
    assert ProviderReceipt(request_id=request_id).safe_request_id() == stored


def test_reconciler_settles_only_stale_records(db):
    now = timezone.now()
    old = now - datetime.timedelta(hours=1)

    def make(status, *, created=now, attempted=None):
        delivery = EmailDelivery.objects.create(template="email-verification", status=status, last_attempt_at=attempted)
        EmailDelivery.objects.filter(pk=delivery.pk).update(created_at=created)
        return delivery

    stale_submitting = make(Status.SUBMITTING, created=old, attempted=old)
    fresh_submitting = make(Status.SUBMITTING, attempted=now)
    stale_pending = make(Status.PENDING, created=old)
    fresh_pending = make(Status.PENDING)
    accepted = make(Status.ACCEPTED, created=old, attempted=old)

    assert service.reconcile_stale_deliveries(now=now) == {"interrupted": 1, "not_submitted": 1}
    statuses = {d.pk: (d.status, d.error_class) for d in EmailDelivery.objects.all()}
    assert statuses[stale_submitting.pk] == (Status.UNKNOWN, "interrupted")
    assert statuses[stale_pending.pk] == (Status.FAILED, "not_submitted")
    assert statuses[fresh_submitting.pk] == (Status.SUBMITTING, "")
    assert statuses[fresh_pending.pk] == (Status.PENDING, "")
    assert statuses[accepted.pk] == (Status.ACCEPTED, "")
    # Idempotent.
    assert service.reconcile_stale_deliveries(now=now) == {"interrupted": 0, "not_submitted": 0}


def test_reconcile_command_reports_counts(db, capsys):
    call_command("reconcile_email_deliveries")
    assert capsys.readouterr().out.strip() == "interrupted=0 not_submitted=0"


@pytest.mark.parametrize(
    ("status", "recoverable"),
    [
        (Status.PENDING, False),
        (Status.SUBMITTING, False),
        (Status.ACCEPTED, False),
        (Status.FAILED, True),
        (Status.UNKNOWN, True),
    ],
)
def test_recoverable_statuses(status, recoverable):
    assert EmailDelivery(template="x", status=status).is_recoverable is recoverable

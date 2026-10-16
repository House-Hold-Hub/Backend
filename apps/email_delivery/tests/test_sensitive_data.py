"""Delivery records and logs never hold the recipient, bearer token, sensitive URL or rendered body (ADR-015)."""

import logging

import pytest
from django.db import transaction

from apps.email_delivery.adapter import ProviderRejected, ProviderTimeout, ProviderUnavailable
from apps.email_delivery.models import EmailDelivery
from apps.email_delivery.service import queue_email

from .conftest import RECIPIENT, SECRET_TOKEN, SECRET_URL

ALLOWED_FIELDS = {
    "id",
    "template",
    "subject_type",
    "subject_id",
    "status",
    "attempt_count",
    "created_at",
    "last_attempt_at",
    "completed_at",
    "provider_request_id",
    "error_class",
}


def test_delivery_schema_is_limited_to_minimal_metadata():
    # A new column (body, address, url, payload...) must be added here deliberately, with security review.
    assert {f.name for f in EmailDelivery._meta.get_fields()} == ALLOWED_FIELDS


def test_message_repr_is_redacted(message):
    for text in (repr(message), str(message), f"{message!r}", repr([message])):
        assert SECRET_TOKEN not in text
        assert RECIPIENT not in text


@pytest.mark.parametrize(
    "outcome",
    [
        None,
        ProviderRejected(f"rejected {RECIPIENT} {SECRET_URL}"),
        ProviderUnavailable(f"503 for {SECRET_URL}"),
        ProviderTimeout(SECRET_URL),
        RuntimeError(f"body={SECRET_URL} to={RECIPIENT}"),
        KeyboardInterrupt(),
    ],
    ids=["accepted", "rejected", "unavailable", "timeout", "unexpected", "interrupted"],
)
def test_no_secret_reaches_persistence_or_logs(
    message, use_provider, django_capture_on_commit_callbacks, caplog, outcome
):
    use_provider(outcome)
    caplog.set_level(logging.DEBUG)
    try:
        with django_capture_on_commit_callbacks(execute=True):
            with transaction.atomic():
                delivery = queue_email(message, template="email-verification", subject_type="user")
    except KeyboardInterrupt:
        delivery = EmailDelivery.objects.get()

    persisted = repr(list(EmailDelivery.objects.values())) + repr(delivery) + str(delivery)
    for haystack in (persisted, caplog.text):
        for secret in (SECRET_TOKEN, SECRET_URL, RECIPIENT, "app.example.test", "Confirm your email"):
            assert secret not in haystack
    # The logs do say what happened, by identifier only.
    assert str(delivery.pk) in caplog.text

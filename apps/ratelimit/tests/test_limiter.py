"""ADR-016 limiter: atomic shared counters, windows, Retry-After, HMAC keys, client IP and fail-closed."""

import datetime
import threading
from unittest import mock

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import DatabaseError, connection
from django.test import RequestFactory, override_settings
from rest_framework.exceptions import Throttled

from apps.ratelimit import limiter
from apps.ratelimit.models import RateLimitBucket

RATES = {
    "test_email": (("email", 3, 60),),
    "test_ip": (("ip", 2, 60),),
    "test_user": (("user", 1, 60),),
    "test_two": (("email", 2, 60), ("email", 1, 3600)),
}
NOW = datetime.datetime(2026, 10, 17, 12, 0, 10, tzinfo=datetime.UTC)


@pytest.fixture(autouse=True)
def rates():
    with override_settings(AUTH_RATE_LIMITS=RATES):
        yield


def at(moment):
    return mock.patch("apps.ratelimit.limiter.timezone.now", return_value=moment)


def request(remote_addr="203.0.113.7", forwarded=None):
    extra = {"REMOTE_ADDR": remote_addr}
    if forwarded is not None:
        extra["HTTP_X_FORWARDED_FOR"] = forwarded
    return RequestFactory().post("/", **extra)


@pytest.mark.django_db
def test_allows_up_to_the_limit_then_throttles_with_retry_after():
    with at(NOW):
        for _ in range(3):
            limiter.consume("test_email", email="a@example.com")
        with pytest.raises(Throttled) as excinfo:
            limiter.consume("test_email", email="a@example.com")
    # The fixed window [12:00:00, 12:01:00) ends 50 s after 12:00:10.
    assert excinfo.value.wait == 50  # type: ignore[attr-defined]
    assert RateLimitBucket.objects.get().hits == 3  # a refused request takes no slot


@pytest.mark.django_db
def test_retry_after_is_rounded_up_and_never_zero():
    moment = NOW.replace(second=59, microsecond=900_000)
    with at(moment):
        for _ in range(3):
            limiter.consume("test_email", email="a@example.com")
        with pytest.raises(Throttled) as excinfo:
            limiter.consume("test_email", email="a@example.com")
    assert excinfo.value.wait == 1  # type: ignore[attr-defined]


@pytest.mark.django_db
def test_a_new_window_starts_counting_again():
    with at(NOW):
        for _ in range(3):
            limiter.consume("test_email", email="a@example.com")
    with at(NOW + datetime.timedelta(seconds=60)):
        limiter.consume("test_email", email="a@example.com")
    assert RateLimitBucket.objects.get().hits == 1


@pytest.mark.django_db
def test_a_lagging_clock_cannot_reset_the_current_window():
    with at(NOW + datetime.timedelta(seconds=60)):
        for _ in range(3):
            limiter.consume("test_email", email="a@example.com")
    # A server whose clock is a minute behind presents the previous window: it counts in the current one.
    with at(NOW), pytest.raises(Throttled):
        limiter.consume("test_email", email="a@example.com")


@pytest.mark.django_db
def test_subjects_are_counted_separately():
    with at(NOW):
        for _ in range(3):
            limiter.consume("test_email", email="a@example.com")
        limiter.consume("test_email", email="b@example.com")


@pytest.mark.django_db
def test_every_rate_of_an_action_applies():
    with at(NOW):
        limiter.consume("test_two", email="a@example.com")
        with pytest.raises(Throttled) as excinfo:
            limiter.consume("test_two", email="a@example.com")  # second rate: 1 per hour
    assert excinfo.value.wait == 3600 - 10  # type: ignore[attr-defined]


@pytest.mark.django_db
def test_per_user_rate():
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(email="u@example.com", name="U")
    with at(NOW):
        limiter.consume("test_user", user=user)
        with pytest.raises(Throttled):
            limiter.consume("test_user", user=user)


@pytest.mark.django_db
def test_clear_resets_the_subject():
    with at(NOW):
        for _ in range(3):
            limiter.consume("test_email", email="a@example.com")
        limiter.clear("test_email", email="a@example.com")
        limiter.consume("test_email", email="a@example.com")


@pytest.mark.django_db
def test_keys_are_hmacs_never_the_subject():
    with at(NOW):
        limiter.consume("test_email", email="private.person@example.com")
        limiter.consume("test_ip", request=request("198.51.100.23"))
    keys = list(RateLimitBucket.objects.values_list("key", flat=True))
    assert all(len(key) == 64 and "example" not in key and "198.51" not in key for key in keys)
    import hashlib

    unkeyed = hashlib.sha256(b"private.person@example.com").hexdigest()
    assert unkeyed not in keys
    with override_settings(SECRET_KEY="another-secret"):
        rate = limiter.rates_for("test_email")[0]
        assert limiter.bucket_key("test_email", rate, "private.person@example.com") not in keys


@pytest.mark.django_db
def test_database_failure_fails_closed():
    with at(NOW), mock.patch.object(connection, "cursor", side_effect=DatabaseError("down")):
        with pytest.raises(DatabaseError):
            limiter.consume("test_email", email="a@example.com")


def test_missing_or_invalid_configuration_is_an_error():
    with pytest.raises(ImproperlyConfigured):
        limiter.rates_for("not_configured")
    with override_settings(AUTH_RATE_LIMITS={"bad": (("ip", 0, 60),)}), pytest.raises(ImproperlyConfigured):
        limiter.rates_for("bad")
    with pytest.raises(ImproperlyConfigured):
        limiter.consume("test_email", email="")


@pytest.mark.django_db
def test_clear_expired_deletes_only_ended_windows():
    with at(NOW):
        limiter.consume("test_email", email="a@example.com")
    with at(NOW + datetime.timedelta(minutes=5)):
        limiter.consume("test_email", email="b@example.com")
    with mock.patch("apps.ratelimit.limiter.timezone.now", return_value=NOW + datetime.timedelta(minutes=2)):
        call_command("clear_expired_rate_limits", stdout=mock.Mock())
    assert RateLimitBucket.objects.count() == 1


# ---- client IP -------------------------------------------------------------------------------------


def test_client_ip_ignores_forwarding_headers_by_default():
    assert limiter.client_ip(request("203.0.113.7", forwarded="198.51.100.1")) == "203.0.113.7"


@override_settings(RATE_LIMIT_TRUSTED_PROXY_COUNT=1)
def test_client_ip_uses_the_entry_appended_by_the_trusted_proxy():
    # The client forged the first entry; the trusted proxy appended the real peer last.
    assert limiter.client_ip(request("10.0.0.2", forwarded="1.2.3.4, 198.51.100.9")) == "198.51.100.9"


@override_settings(RATE_LIMIT_TRUSTED_PROXY_COUNT=2)
def test_client_ip_without_enough_proxy_hops_shares_one_bucket():
    assert limiter.client_ip(request("10.0.0.2", forwarded="198.51.100.9")) == "unknown"


def test_ipv6_clients_are_grouped_by_their_64_prefix():
    first = limiter.client_ip(request("2001:db8:1:2:aaaa::1"))
    second = limiter.client_ip(request("2001:db8:1:2:bbbb::2"))
    assert first == second == "2001:db8:1:2::"
    assert limiter.client_ip(request("::ffff:203.0.113.7")) == "203.0.113.7"


def test_unparseable_address_shares_one_bucket():
    assert limiter.client_ip(request("")) == "unknown"


# ---- concurrency -----------------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_concurrent_requests_never_exceed_the_limit():
    workers = 12
    barrier = threading.Barrier(workers)
    allowed, refused = [], []

    def attempt():
        try:
            barrier.wait()
            with at(NOW):
                limiter.consume("test_email", email="race@example.com")
            allowed.append(1)
        except Throttled:
            refused.append(1)
        finally:
            connection.close()

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(allowed) == 3
    assert len(refused) == workers - 3
    assert RateLimitBucket.objects.get().hits == 3

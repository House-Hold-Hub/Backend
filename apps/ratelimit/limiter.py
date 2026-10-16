"""ADR-016 authentication rate limiter: shared, atomic, PostgreSQL-backed fixed-window counters.

The rates live in ``settings.AUTH_RATE_LIMITS`` as ``{action: ((per, limit, window_seconds), ...)}`` with
``per`` one of ``"ip"``, ``"email"`` or ``"user"``. ``consume`` checks and takes a slot of every rate of an
action in one ``INSERT ... ON CONFLICT DO UPDATE ... WHERE ... RETURNING`` statement per rate: PostgreSQL
locks the conflicting row for the update, so concurrent requests for the same key are serialized and can
never together exceed the limit (a read-then-write through Django's cache API cannot guarantee this). A
refused request raises DRF's ``Throttled``, which the API error handler turns into ``429 RATE_LIMITED``
with ``Retry-After``.

Fail closed: a database error while recording a request propagates, so the request fails instead of
running unlimited. Call ``consume`` outside the domain transaction, so a rolled-back request still
counts.

django-allauth's own limiter is disabled (``ACCOUNT_RATE_LIMITS = False``): ADR-016 explains why it does
not conform.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac
from rest_framework.exceptions import Throttled

from .models import RateLimitBucket

KEY_SALT = "householdhub.ratelimit"
SUBJECTS = ("ip", "email", "user")

_CONSUME = f"""
INSERT INTO {RateLimitBucket._meta.db_table} AS b (key, window_start, hits, expires_at)
VALUES (%(key)s, %(start)s, 1, %(end)s)
ON CONFLICT (key) DO UPDATE SET
    hits = CASE WHEN EXCLUDED.window_start > b.window_start THEN 1 ELSE b.hits + 1 END,
    window_start = GREATEST(b.window_start, EXCLUDED.window_start),
    expires_at = GREATEST(b.expires_at, EXCLUDED.expires_at)
WHERE EXCLUDED.window_start > b.window_start OR b.hits < %(limit)s
RETURNING hits
"""
# A window only ever moves forward (GREATEST), so an application server whose clock lags behind
# cannot reset a counter by presenting an older window: its hits count in the current one.


@dataclass(frozen=True)
class Rate:
    per: str
    limit: int
    window: int  # seconds


def rates_for(action: str) -> tuple[Rate, ...]:
    configured = getattr(settings, "AUTH_RATE_LIMITS", {}).get(action)
    if configured is None:
        raise ImproperlyConfigured(f"No rate limit configured for {action!r} (AUTH_RATE_LIMITS, ADR-016).")
    rates = tuple(Rate(*rate) for rate in configured)
    for rate in rates:
        if rate.per not in SUBJECTS or rate.limit < 1 or rate.window < 1:
            raise ImproperlyConfigured(f"Invalid rate {rate!r} for {action!r}.")
    return rates


def client_ip(request) -> str:
    """The client address used as a rate-limit subject (ADR-016 "Client IP").

    The peer address, unless ``RATE_LIMIT_TRUSTED_PROXY_COUNT`` says how many proxies Infrastructure
    put in front of the service: only then is the address that the outermost trusted proxy appended to
    ``X-Forwarded-For`` used. Client-supplied forwarding entries are never trusted. IPv6 addresses are
    grouped by their ``RATE_LIMIT_IPV6_PREFIX`` network, since a single client usually controls a whole
    /64. An address that cannot be parsed shares one bucket rather than escaping the limit.
    """
    address = request.META.get("REMOTE_ADDR", "")
    proxies = getattr(settings, "RATE_LIMIT_TRUSTED_PROXY_COUNT", 0)
    if proxies:
        hops = [hop.strip() for hop in request.META.get("HTTP_X_FORWARDED_FOR", "").split(",") if hop.strip()]
        address = hops[-proxies] if len(hops) >= proxies else ""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        prefix = getattr(settings, "RATE_LIMIT_IPV6_PREFIX", 64)
        return str(ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False).network_address)
    return str(ip)


def _subject(rate: Rate, *, request, email: str | None, user) -> str:
    if rate.per == "ip":
        if request is None:
            raise ImproperlyConfigured("An IP rate needs the request.")
        return client_ip(request)
    if rate.per == "email":
        if not email:
            raise ImproperlyConfigured("An email rate needs the normalized email address.")
        return email
    if user is None or user.pk is None:
        raise ImproperlyConfigured("A user rate needs a saved user.")
    return str(user.pk)


def bucket_key(action: str, rate: Rate, subject: str) -> str:
    """HMAC-SHA256 under the server secret: the stored key never reveals the address or IP."""
    value = "\x00".join((action, rate.per, str(rate.window), subject))
    return salted_hmac(KEY_SALT, value, algorithm="sha256").hexdigest()


def _window(now: datetime, window: int) -> tuple[datetime, datetime]:
    start = datetime.fromtimestamp(math.floor(now.timestamp() / window) * window, tz=UTC)
    return start, start + timedelta(seconds=window)


def _retry_after(key: str, now: datetime) -> int:
    expires_at = RateLimitBucket.objects.filter(key=key).values_list("expires_at", flat=True).first()
    if expires_at is None:
        return 1
    return max(1, math.ceil((expires_at - now).total_seconds()))


def consume(action: str, *, request=None, email: str | None = None, user=None) -> None:
    """Take one slot of every rate of ``action``, or raise ``Throttled`` with the seconds to wait.

    Rates are consumed in their configured order and the first exhausted one refuses the request
    (slots already taken from earlier rates stay taken, which only makes the limit stricter).
    """
    now = timezone.now()
    for rate in rates_for(action):
        key = bucket_key(action, rate, _subject(rate, request=request, email=email, user=user))
        start, end = _window(now, rate.window)
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(_CONSUME, {"key": key, "start": start, "end": end, "limit": rate.limit})
            allowed = cursor.fetchone() is not None
            if not allowed:
                raise Throttled(wait=_retry_after(key, now))


def clear(action: str, *, request=None, email: str | None = None, user=None) -> None:
    """Reset every counter of ``action`` for this subject (a successful login clears its failures)."""
    keys = [
        bucket_key(action, rate, _subject(rate, request=request, email=email, user=user)) for rate in rates_for(action)
    ]
    RateLimitBucket.objects.filter(key__in=keys).delete()


def clear_expired(*, now: datetime | None = None) -> int:
    deleted, _ = RateLimitBucket.objects.filter(expires_at__lte=now or timezone.now()).delete()
    return deleted

"""The provider-neutral email boundary (ADR-015, decision gate D02).

Nothing here names a vendor. A concrete provider is a class with a ``send`` method that raises only
the exceptions below; the managed provider is chosen later (D02) behind this interface.

The message, and above all its rendered body, exists only in memory for the duration of the
post-commit call. It is never persisted and its ``repr`` is redacted so that log lines, tracebacks and
``on_commit`` bookkeeping cannot leak the recipient or a secret-bearing link.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

MAX_TIMEOUT_SECONDS = 30.0
# Deliberately narrow: no "@" or ".", so an address or hostname can never pass as a request id.
_REQUEST_ID = re.compile(r"[A-Za-z0-9_:-]{1,128}")


@dataclass(frozen=True, repr=False)
class EmailMessage:
    """One rendered transactional email. May carry bearer material: keep it out of persistence and logs."""

    to: str
    subject: str
    text_body: str
    html_body: str = ""

    def __repr__(self):
        return "EmailMessage(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class ProviderReceipt:
    """What a provider returns when it *accepts* a submission. Acceptance is not inbox delivery."""

    request_id: str = field(default="")

    def safe_request_id(self) -> str:
        """The provider's request identifier if it is a plain token, else empty (never arbitrary text)."""
        return self.request_id if isinstance(self.request_id, str) and _REQUEST_ID.fullmatch(self.request_id) else ""


class ProviderError(Exception):
    """Base class of every failure a provider may raise. Messages are never stored or logged.

    A bare ``ProviderError`` (or a subclass that does not say otherwise) is an unclassified failure:
    the provider may have accepted the message, so the outcome is recorded as unknown.
    """

    error_class = "unexpected"


# Error classes that state the provider did NOT accept the message; every other class is "unknown".
DEFINITIVE_REFUSALS = frozenset({"not_configured", "unavailable", "rejected"})


class ProviderNotConfigured(ProviderError):
    """No provider is selected (D02 is open): nothing was submitted."""

    error_class = "not_configured"


class ProviderUnavailable(ProviderError):
    """The provider was unreachable or refused to take the submission (connection, 5xx): not accepted."""

    error_class = "unavailable"


class ProviderRejected(ProviderError):
    """The provider definitively refused this message (4xx, bad recipient): not accepted."""

    error_class = "rejected"


class ProviderTimeout(ProviderError):
    """The bounded call expired. The provider may or may not have accepted the message: outcome unknown."""

    error_class = "timeout"


class EmailProvider(Protocol):
    """A transactional email provider.

    ``send`` must return only after the provider accepted the message, and must give up after
    ``timeout`` seconds (raising ``ProviderTimeout``). ``idempotency_key`` is stable for one delivery
    so a provider that supports de-duplication can use it.
    """

    def send(self, message: EmailMessage, *, idempotency_key: str, timeout: float) -> ProviderReceipt: ...


class UnconfiguredProvider:
    """Default until D02 is resolved: records an honest failure instead of pretending to send."""

    def send(self, message, *, idempotency_key, timeout):
        raise ProviderNotConfigured


def delivery_settings() -> dict[str, Any]:
    """The validated ``EMAIL_DELIVERY`` setting."""
    config: dict[str, Any] = dict(settings.EMAIL_DELIVERY)
    timeout = config["TIMEOUT_SECONDS"]
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ImproperlyConfigured(f"EMAIL_DELIVERY['TIMEOUT_SECONDS'] must be in (0, {MAX_TIMEOUT_SECONDS}].")
    if config["STALE_AFTER_SECONDS"] <= timeout:
        raise ImproperlyConfigured("EMAIL_DELIVERY['STALE_AFTER_SECONDS'] must exceed the provider timeout.")
    limit = config["MAX_BACKGROUND_SUBMISSIONS"]
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ImproperlyConfigured("EMAIL_DELIVERY['MAX_BACKGROUND_SUBMISSIONS'] must be a positive integer.")
    return config


def get_provider() -> EmailProvider:
    return import_string(delivery_settings()["PROVIDER"])()

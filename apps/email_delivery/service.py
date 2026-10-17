"""ADR-015 sequence: commit domain state -> ``transaction.on_commit()`` -> bounded provider call -> durable status.

``queue_email`` runs inside the domain transaction and persists the delivery record with it, so a
rollback discards both the state and the email. After the commit, ``_submit`` claims the record
(persisted *before* the provider call), makes one bounded synchronous call, and persists the honest
outcome. It never raises for a provider problem: the domain transaction has already committed and must
stay committed. There is no queue or retry loop; recovery is a new delivery (resend) driven by the
domain flow, and ``reconcile_stale_deliveries`` settles records an interrupted process left behind.
"""

import datetime
import logging
import threading
import time
from functools import partial
from typing import Any

from django.db import DatabaseError, connection, transaction
from django.db.models import Q
from django.utils import timezone

from .adapter import (
    DEFINITIVE_REFUSALS,
    EmailMessage,
    ProviderError,
    ProviderReceipt,
    delivery_settings,
    get_provider,
)
from .models import EmailDelivery

logger = logging.getLogger(__name__)

Status = EmailDelivery.Status


class EmailDeliveryError(Exception):
    """The email cannot be queued safely (programming error, e.g. outside a transaction)."""


class DeferredSubmissions:
    """Post-commit submissions that run after the HTTP response was handed to the server.

    For an operation whose response time must not reveal whether a provider call happened (an
    enumeration-safe password-reset request): ``queue_email(..., defer=...)`` hands the committed delivery
    here instead of calling the provider inside the request, and the response's ``close()`` calls
    ``run_in_background``. The sequence is still commit -> bounded provider call -> durable status (ADR-015);
    only the request no longer waits for it, and neither does its web worker.

    The call runs on a short-lived, non-daemon thread with its own database connection, which is closed as soon
    as the submission is done. Concurrency is bounded per process by ``EMAIL_DELIVERY["MAX_BACKGROUND_SUBMISSIONS"]``
    and there is no queue: when every slot is busy the submission is dropped and its delivery stays ``pending``
    (nothing was sent; ``reconcile_stale_deliveries`` settles it as ``failed`` / ``not_submitted``).

    ``uniform=True`` makes the slot itself existence-independent: the caller admits *every* valid request,
    including those with nothing to submit (unknown, disabled or passwordless addresses), and each admitted
    request holds its slot for exactly ``EMAIL_DELIVERY["BACKGROUND_SLOT_SECONDS"]`` (longer than the provider
    timeout, so a submission always fits) however fast or slow the provider was. Slot occupancy and the
    admission decision then depend only on how many valid requests are in flight, never on which addresses have
    accounts, so one caller cannot learn about another address from whether its own email was submitted. The
    refused path does no database work for either kind of request.
    """

    def __init__(self, *, uniform: bool = False) -> None:
        self._uniform = uniform
        self._pending: list[tuple[Any, EmailMessage]] = []

    def add(self, delivery_id, message: EmailMessage) -> None:
        self._pending.append((delivery_id, message))

    def run(self) -> None:
        """Submit each delivery once, on the calling thread; idempotent. A failure of one never skips another."""
        pending, self._pending = self._pending, []
        _submit_all(pending)

    def run_in_background(self) -> None:
        """Submit on a bounded background thread; returns at once and never raises."""
        pending, self._pending = self._pending, []
        if not pending and not self._uniform:
            return
        config = delivery_settings()
        hold = config["BACKGROUND_SLOT_SECONDS"] if self._uniform else 0.0
        thread = threading.Thread(target=_run_and_close, args=(pending, hold), name="deferred-email-submission")
        with _background_lock:
            admitted = len(_background_threads) < config["MAX_BACKGROUND_SUBMISSIONS"]
            if admitted:
                _background_threads.append(thread)
        if admitted:
            try:
                thread.start()
            except Exception:  # e.g. the process cannot start another thread
                with _background_lock:
                    _background_threads.remove(thread)
                admitted = False
        if not admitted:
            # Identical for every kind of request; the deliveries (if any) stay pending for the reconciler.
            logger.warning("deferred email submission dropped: no free background slot")


_background_lock = threading.Lock()
_background_threads: list[threading.Thread] = []


def _run_and_close(pending: list[tuple[Any, EmailMessage]], hold: float) -> None:
    started = time.monotonic()
    try:
        try:
            _submit_all(pending)
        except BaseException:
            # Interrupted mid-call: _submit already recorded unknown / interrupted. The thread ends either way.
            logger.warning("deferred email submission interrupted")
        finally:
            connection.close()  # as soon as the work is done, not after the hold
        remaining = started + hold - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    finally:
        with _background_lock:
            _background_threads.remove(threading.current_thread())


def join_background_submissions(timeout: float = 10.0) -> None:
    """Wait for submissions started by ``run_in_background`` (tests; the interpreter does it at exit)."""
    with _background_lock:
        threads = list(_background_threads)
    for thread in threads:
        thread.join(timeout)


def _submit_all(pending: list[tuple[Any, EmailMessage]]) -> None:
    for delivery_id, message in pending:
        try:
            _submit(delivery_id, message)
        except Exception:
            # _submit only raises for what it cannot classify; never log it (it could echo a recipient or link).
            logger.error("email delivery %s: submission failed unexpectedly", delivery_id)


def queue_email(
    message: EmailMessage,
    *,
    template: str,
    subject_type: str = "",
    subject_id=None,
    defer: DeferredSubmissions | None = None,
) -> EmailDelivery:
    """Record a delivery in the current domain transaction and submit it only after that commit.

    ``template``, ``subject_type`` and ``subject_id`` are non-secret identifiers (for example
    ``"email-verification"``, ``"invitation"`` and the invitation's UUID). The message is held in memory
    for the post-commit call only. With ``defer`` the committed submission waits in it until the caller
    runs it after the response (``DeferredSubmissions``).
    """
    if not connection.in_atomic_block:
        raise EmailDeliveryError("queue_email must run inside the domain transaction (transaction.atomic()).")
    delivery = EmailDelivery.objects.create(template=template, subject_type=subject_type, subject_id=subject_id)
    # robust=True: even an unforeseen error here must not skip other on_commit callbacks.
    callback = partial(_submit, delivery.pk, message) if defer is None else partial(defer.add, delivery.pk, message)
    transaction.on_commit(callback, robust=True)
    return delivery


def _submit(delivery_id, message: EmailMessage) -> None:
    now = timezone.now()
    try:
        # The reconciler ages "pending" from created_at, which predates the commit. If a long domain
        # transaction lost that race, the callback's own run proves nothing was submitted yet, so it
        # may still claim a record the reconciler marked "not_submitted".
        claimable = Q(status=Status.PENDING) | Q(status=Status.FAILED, error_class="not_submitted")
        claimed = EmailDelivery.objects.filter(claimable, pk=delivery_id).update(
            status=Status.SUBMITTING, attempt_count=1, last_attempt_at=now, error_class="", completed_at=None
        )
    except DatabaseError:
        # Cannot persist the claim, so do not submit: the record stays pending and nothing was sent.
        logger.error("email delivery %s: could not claim, not submitted", delivery_id)
        return
    if not claimed:
        return  # Already claimed (or settled): never submit twice.

    status, error_class, request_id = _call_provider(delivery_id, message)
    try:
        _record_outcome(delivery_id, status, error_class, request_id)
    except DatabaseError:
        # The record stays "submitting"; reconcile_stale_deliveries turns it into "unknown".
        # Success is never reported without a persisted status.
        logger.error("email delivery %s: outcome %s could not be persisted", delivery_id, status)
        return
    if status == Status.ACCEPTED:
        logger.info("email delivery %s: accepted by provider", delivery_id)
    else:
        logger.warning("email delivery %s: %s (%s)", delivery_id, status, error_class)


def _call_provider(delivery_id, message: EmailMessage) -> tuple[str, str, str]:
    """One bounded provider call, mapped to (status, safe error class, provider request id)."""
    try:
        receipt = get_provider().send(
            message, idempotency_key=str(delivery_id), timeout=delivery_settings()["TIMEOUT_SECONDS"]
        )
    except ProviderError as exc:
        # Only the fixed class is kept; the exception text may echo a recipient, URL or body.
        status = Status.FAILED if exc.error_class in DEFINITIVE_REFUSALS else Status.UNKNOWN
        return status, exc.error_class, ""
    except Exception:
        return Status.UNKNOWN, "unexpected", ""
    except BaseException:
        # Interrupted (SystemExit, KeyboardInterrupt): the provider may have accepted it.
        try:
            _record_outcome(delivery_id, Status.UNKNOWN, "interrupted", "")
        except DatabaseError:
            pass  # stays "submitting"; the reconciler settles it
        logger.warning("email delivery %s: interrupted during the provider call", delivery_id)
        raise
    if not isinstance(receipt, ProviderReceipt):
        return Status.UNKNOWN, "unexpected", ""
    return Status.ACCEPTED, "", receipt.safe_request_id()


def _record_outcome(delivery_id, status: str, error_class: str, request_id: str) -> None:
    EmailDelivery.objects.filter(pk=delivery_id, status=Status.SUBMITTING).update(
        status=status, error_class=error_class, provider_request_id=request_id, completed_at=timezone.now()
    )


def reconcile_stale_deliveries(*, now: datetime.datetime | None = None) -> dict[str, int]:
    """Settle records an interrupted process left behind. Idempotent; schedule it like other cleanup commands.

    * ``submitting`` past the stale window -> ``unknown`` / ``interrupted`` (the provider may have accepted).
    * ``pending`` past the stale window -> ``failed`` / ``not_submitted`` (the callback never claimed it,
      so nothing was sent).
    """
    now = now or timezone.now()
    cutoff = now - datetime.timedelta(seconds=delivery_settings()["STALE_AFTER_SECONDS"])
    interrupted = EmailDelivery.objects.filter(status=Status.SUBMITTING, last_attempt_at__lt=cutoff).update(
        status=Status.UNKNOWN, error_class="interrupted", completed_at=now
    )
    not_submitted = EmailDelivery.objects.filter(status=Status.PENDING, created_at__lt=cutoff).update(
        status=Status.FAILED, error_class="not_submitted", completed_at=now
    )
    return {"interrupted": interrupted, "not_submitted": not_submitted}

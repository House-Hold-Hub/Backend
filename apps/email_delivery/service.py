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
from collections.abc import Callable
from functools import partial

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
    only the request no longer waits for it, and neither does its web worker: the bounded call runs on a
    short-lived thread with its own connection, so a slow provider cannot keep a synchronous worker busy
    (which would be a timing channel, since only eligible accounts submit). If the process dies before the
    call, the record stays ``pending`` and the reconciler settles it as ``not_submitted``.
    """

    def __init__(self) -> None:
        self._pending: list[Callable[[], None]] = []

    def add(self, submission: Callable[[], None]) -> None:
        self._pending.append(submission)

    def run(self) -> None:
        """Run each submission once; idempotent. ``_submit`` never raises for a provider problem."""
        while self._pending:
            self._pending.pop(0)()

    def run_in_background(self) -> None:
        """Run the submissions on their own thread and database connection; returns at once."""
        if not self._pending:
            return
        thread = threading.Thread(target=self._run_and_close, name="deferred-email-submission", daemon=True)
        with _background_lock:
            _background_threads.append(thread)
        thread.start()

    def _run_and_close(self) -> None:
        try:
            self.run()
        except Exception:
            # Never log the exception: it could echo a recipient or link. The record stays for the reconciler.
            logger.error("deferred email submission failed")
        finally:
            connection.close()
            with _background_lock:
                _background_threads.remove(threading.current_thread())


_background_lock = threading.Lock()
_background_threads: list[threading.Thread] = []


def join_background_submissions(timeout: float = 10.0) -> None:
    """Wait for submissions started by ``run_in_background`` (graceful shutdown, tests)."""
    with _background_lock:
        threads = list(_background_threads)
    for thread in threads:
        thread.join(timeout)


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
    submission = partial(_submit, delivery.pk, message)
    # robust=True: even an unforeseen error here must not skip other on_commit callbacks.
    transaction.on_commit(submission if defer is None else partial(defer.add, submission), robust=True)
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

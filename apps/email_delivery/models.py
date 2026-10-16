import uuid

from django.db import models
from django.db.models import Q


class EmailDelivery(models.Model):
    """Durable, minimal state of one transactional email submission (ADR-015).

    Deliberately holds no recipient address, token, link or body (security model, "Transactional email
    security"): only identifiers, status, attempt timing/count, the provider's request identifier and a
    safe error class. A failed or unknown delivery is recovered by the owning domain flow issuing a new
    delivery (resend with a fresh token), because the message itself is never kept.
    """

    class Status(models.TextChoices):
        # Recorded in the domain transaction; the post-commit callback has not claimed it. If this
        # outlives the callback window the process died before submitting, and nothing was sent.
        PENDING = "pending"
        # Claimed and persisted before the provider call. Left behind only if the process was
        # interrupted during the call: the provider may or may not have accepted.
        SUBMITTING = "submitting"
        # The provider accepted the submission. This is NOT confirmation of inbox delivery.
        ACCEPTED = "accepted"
        # The provider did not accept (rejected, unavailable, not configured, or never submitted).
        FAILED = "failed"
        # The outcome cannot be known (timeout, interrupted call, unexpected error).
        UNKNOWN = "unknown"

    RECOVERABLE_STATUSES = (Status.FAILED, Status.UNKNOWN)

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    template = models.SlugField(max_length=64)
    subject_type = models.SlugField(max_length=64, blank=True)
    subject_id = models.UUIDField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    provider_request_id = models.CharField(max_length=128, blank=True)
    error_class = models.CharField(max_length=32, blank=True)

    class Meta:
        indexes = [models.Index(fields=["status", "created_at"], name="email_delivery_status_idx")]
        constraints = [
            models.CheckConstraint(
                condition=Q(status__in=["pending", "submitting", "accepted", "failed", "unknown"]),
                name="email_delivery_status_valid",
            ),
        ]

    def __str__(self):
        return f"EmailDelivery({self.id}, {self.status})"

    @property
    def is_recoverable(self) -> bool:
        return self.status in self.RECOVERABLE_STATUSES

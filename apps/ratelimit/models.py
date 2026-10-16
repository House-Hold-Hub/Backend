from django.db import models


class RateLimitBucket(models.Model):
    """One fixed-window counter of the ADR-016 rate limiter (``limiter.py``).

    ``key`` is an HMAC of the action, rate and subject (client IP, email address or user id) under a
    server-side secret, so no address or IP is stored in plaintext or as an unkeyed digest. A row is
    only ever written by the single atomic statement in ``limiter.consume``; ``expires_at`` is the end of
    its current window, after which ``clear_expired_rate_limits`` may delete it.
    """

    key = models.CharField(max_length=64, primary_key=True)
    window_start = models.DateTimeField()
    hits = models.PositiveIntegerField()
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        db_table = "ratelimit_bucket"

    def __str__(self):
        return f"RateLimitBucket({self.hits} until {self.expires_at.isoformat()})"

from django.core.management.base import BaseCommand

from apps.ratelimit.limiter import clear_expired


class Command(BaseCommand):
    help = "Delete rate-limit counters whose window has ended (ADR-016). Idempotent; schedule it like session cleanup."

    def handle(self, *args, **options):
        deleted = clear_expired()
        self.stdout.write(f"Deleted {deleted} expired rate-limit counters.")

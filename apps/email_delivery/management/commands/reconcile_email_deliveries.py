from django.core.management.base import BaseCommand

from apps.email_delivery.service import reconcile_stale_deliveries


class Command(BaseCommand):
    help = "Settle email deliveries left pending or submitting by an interrupted process (ADR-015). Idempotent."

    def handle(self, *args, **options):
        counts = reconcile_stale_deliveries()
        self.stdout.write(f"interrupted={counts['interrupted']} not_submitted={counts['not_submitted']}")

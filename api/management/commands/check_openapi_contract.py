from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from api.contract import ContractValidationError, check_current_implementation


class Command(BaseCommand):
    help = "Validate implemented API operations against the pinned Documentation OpenAPI contract."

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            implemented_count, contract_count, revision = check_current_implementation()
        except (ContractValidationError, OSError, UnicodeError) as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                "OpenAPI contract check passed: "
                f"{implemented_count} implemented operations are covered by "
                f"{contract_count} contract operations at Documentation@{revision}."
            )
        )

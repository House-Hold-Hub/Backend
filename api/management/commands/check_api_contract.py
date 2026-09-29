from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError, CommandParser

from api.contract import ContractCheckError, validate_contract


class Command(BaseCommand):
    help = "Compare implemented Backend API operations with the canonical OpenAPI contract."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "contract",
            type=Path,
            help="Path to House-Hold-Hub/Documentation/api/openapi.yaml",
        )

    def handle(self, *args: object, **options: object) -> None:
        contract_path = options.get("contract")
        if not isinstance(contract_path, Path):
            raise CommandError("contract path is required")

        try:
            result = validate_contract(contract_path)
        except ContractCheckError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                "API contract check passed: "
                f"{len(result.implemented)} implemented operation(s) are declared in "
                f"{contract_path} ({len(result.contract)} canonical operation(s))."
            )
        )

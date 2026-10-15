from django.core.management.base import BaseCommand, CommandError

from apps.api import contract


class Command(BaseCommand):
    help = (
        "Fail if the implemented /api/v1 operations diverge from the Documentation-owned OpenAPI "
        "contract at the revision pinned in contract/documentation-revision.json."
    )

    def add_arguments(self, parser):
        parser.add_argument("--spec", required=True, help="Path to api/openapi.yaml from the pinned Documentation commit.")
        parser.add_argument("--pin", default=str(contract.PIN_PATH), help="Pin file (default: contract/documentation-revision.json).")

    def handle(self, *args, spec, pin, **options):
        try:
            pinned = contract.load_pin(pin)
            document = contract.load_contract(spec, pinned)
        except contract.ContractError as exc:
            raise CommandError(str(exc)) from exc
        report = contract.check(document)
        self.stdout.write(
            f"Contract {pinned.repository}@{pinned.commit[:12]} (sha256 verified): "
            f"{report.implemented}/{report.total} operations implemented."
        )
        if not report.ok:
            for finding in report.findings:
                self.stderr.write(str(finding))
            raise CommandError(f"{len(report.findings)} contract divergence(s) found.")
        self.stdout.write(self.style.SUCCESS("No divergence in implemented operations."))

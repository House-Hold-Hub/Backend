import pytest

from apps.email_delivery import service
from apps.email_delivery.adapter import EmailMessage
from apps.email_delivery.testing import RecordingProvider

SECRET_TOKEN = "sentinel-bearer-material"
SECRET_URL = f"https://app.example.test/verify#token={SECRET_TOKEN}"
RECIPIENT = "private.person@example.test"


@pytest.fixture(autouse=True)
def _database(db):
    """Every test here touches the delivery table."""


@pytest.fixture
def message():
    return EmailMessage(
        to=RECIPIENT,
        subject="Confirm your email",
        text_body=f"Open {SECRET_URL} to confirm.",
        html_body=f'<a href="{SECRET_URL}">Confirm</a>',
    )


@pytest.fixture
def use_provider(monkeypatch):
    """Install a provider test double behind the adapter boundary and return it."""

    def install(outcome=None, *, provider=None, **kwargs):
        provider = provider or RecordingProvider(outcome, **kwargs)
        monkeypatch.setattr(service, "get_provider", lambda: provider)
        return provider

    return install

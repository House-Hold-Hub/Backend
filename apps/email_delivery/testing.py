"""Provider test doubles. Production code never imports this module."""

from .adapter import EmailMessage, ProviderReceipt, ProviderTimeout


class RecordingProvider:
    """Accepts every message and remembers it, like Django's locmem backend.

    ``outcome`` is ``None`` to accept, an exception instance to raise, or a callable run on each send.
    ``latency`` simulates a slow provider: a call whose latency exceeds the timeout it was given raises
    ``ProviderTimeout``, as a real client with that socket timeout would.
    """

    def __init__(self, outcome=None, *, request_id="req-1", latency=0.0):
        self.outcome = outcome
        self.request_id = request_id
        self.latency = latency
        self.sent: list[EmailMessage] = []
        self.calls: list[dict] = []

    def send(self, message, *, idempotency_key, timeout):
        self.calls.append({"idempotency_key": idempotency_key, "timeout": timeout})
        if self.latency > timeout:
            raise ProviderTimeout("simulated")
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            self.outcome(message)
        self.sent.append(message)
        return ProviderReceipt(request_id=self.request_id)

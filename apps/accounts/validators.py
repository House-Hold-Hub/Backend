"""Password validators completing Django's for the ADR-016 password policy."""

from django.core.exceptions import ValidationError
from django.utils.translation import ngettext


class MaximumLengthValidator:
    """Reject passwords longer than ``max_length`` Unicode code points (ADR-016: at least 128 accepted).

    Django ships only a minimum; the bound keeps hashing cost predictable and matches the contract's
    ``maxLength``. Over-long input is rejected, never truncated.
    """

    def __init__(self, max_length=128):
        self.max_length = max_length

    def validate(self, password, user=None):
        if len(password) > self.max_length:
            raise ValidationError(
                ngettext(
                    "This password is too long. It must contain at most %(max_length)d character.",
                    "This password is too long. It must contain at most %(max_length)d characters.",
                    self.max_length,
                ),
                code="password_too_long",
                params={"max_length": self.max_length},
            )

    def get_help_text(self):
        return ngettext(
            "Your password must contain at most %(max_length)d character.",
            "Your password must contain at most %(max_length)d characters.",
            self.max_length,
        ) % {"max_length": self.max_length}

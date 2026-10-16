"""Request-body building blocks for contract schemas with ``additionalProperties: false``."""

from rest_framework import serializers


def _has_lone_surrogate(value: str) -> bool:
    # JSON allows "\\ud800" on its own; such a string cannot be encoded as UTF-8 for hashing or storage.
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


class StrictCharField(serializers.CharField):
    """A JSON string only: numbers and booleans are not coerced, unpaired surrogates are invalid."""

    default_error_messages = {
        "not_a_string": "Must be a string.",
        "surrogate": "Must be valid Unicode text.",
    }

    def to_internal_value(self, data):
        if not isinstance(data, str):
            self.fail("not_a_string")
        if _has_lone_surrogate(data):
            self.fail("surrogate")
        return super().to_internal_value(data)


class StrictEmailField(StrictCharField, serializers.EmailField):
    pass


class StrictSerializer(serializers.Serializer):
    """Rejects properties the schema does not declare (the contract's ``additionalProperties: false``)."""

    default_error_messages = {"unknown_field": "Unknown field."}

    def to_internal_value(self, data):
        if isinstance(data, dict):
            unknown = sorted(set(data) - set(self.fields))
            if unknown:
                raise serializers.ValidationError({name: [self.error_messages["unknown_field"]] for name in unknown})
        return super().to_internal_value(data)

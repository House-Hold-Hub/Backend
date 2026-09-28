from __future__ import annotations

import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import UUIDField

from users.models import User


def test_custom_uuid_user_is_configured() -> None:
    assert settings.AUTH_USER_MODEL == "users.User"
    assert get_user_model() is User
    assert isinstance(User._meta.pk, UUIDField)
    assert isinstance(User(username="scaffold-check").id, uuid.UUID)


def test_postgresql_backend_is_the_default() -> None:
    assert settings.DATABASES["default"]["ENGINE"] == "django.db.backends.postgresql"


def test_same_origin_default_has_no_cors_layer() -> None:
    configured_layers = [*settings.INSTALLED_APPS, *settings.MIDDLEWARE]
    assert not any("cors" in layer.lower() for layer in configured_layers)

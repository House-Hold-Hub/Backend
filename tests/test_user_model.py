from __future__ import annotations

import importlib
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import migrations
from django.db.models import UUIDField

from users.models import User


def test_custom_user_identity_model_contract() -> None:
    assert settings.AUTH_USER_MODEL == "users.User"
    assert get_user_model() is User

    assert isinstance(User._meta.pk, UUIDField)
    assert User._meta.pk.primary_key
    assert isinstance(User(username="identity-check").id, uuid.UUID)

    assert User.set_password is AbstractBaseUser.set_password
    assert User.check_password is AbstractBaseUser.check_password

    field_names = {field.name for field in User._meta.get_fields()}
    assert "password_hash" not in field_names
    assert "google_id" not in field_names


def test_initial_migration_contains_only_the_custom_user_model() -> None:
    migration_module = importlib.import_module("users.migrations.0001_initial")
    migration_class = getattr(migration_module, "Migration")

    assert migration_class.initial is True
    assert migration_class.dependencies == [("auth", "0012_alter_user_first_name_max_length")]

    create_models = [
        operation
        for operation in migration_class.operations
        if isinstance(operation, migrations.CreateModel)
    ]
    assert [operation.name for operation in create_models] == ["User"]

    fields = dict(create_models[0].fields)
    assert isinstance(fields["id"], UUIDField)
    assert fields["id"].primary_key
    assert fields["id"].default is uuid.uuid4
    assert "password" in fields
    assert "password_hash" not in fields
    assert "google_id" not in fields

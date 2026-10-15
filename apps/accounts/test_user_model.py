import uuid

from django.contrib.auth import get_user_model
from django.db import models


def test_auth_user_model_is_uuid_pk():
    user_model = get_user_model()
    assert user_model._meta.label == "accounts.User"
    pk = user_model._meta.pk
    assert isinstance(pk, models.UUIDField)
    assert pk.default is uuid.uuid4


def test_no_bespoke_password_or_provider_fields():
    names = {f.name for f in get_user_model()._meta.get_fields()}
    assert "password_hash" not in names
    assert "google_id" not in names

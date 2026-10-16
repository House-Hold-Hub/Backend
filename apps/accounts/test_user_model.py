import sys
import uuid

import pytest
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction

User = get_user_model()


# ---- shape of the model (no database) -------------------------------------------------------


def test_auth_user_model_is_uuid_pk():
    assert User._meta.label == "accounts.User"
    pk = User._meta.pk
    assert isinstance(pk, models.UUIDField)
    assert pk.default is uuid.uuid4


def test_no_bespoke_password_provider_or_verification_fields():
    names = {f.name for f in User._meta.get_fields()}
    assert "password_hash" not in names
    assert "google_id" not in names
    assert "email_verified" not in names
    assert not {n for n in names if "verif" in n}
    # The password is Django's own field.
    assert isinstance(User._meta.get_field("password"), models.CharField)


def test_identity_fields():
    assert User.USERNAME_FIELD == "email"
    assert User.EMAIL_FIELD == "email"
    assert User.REQUIRED_FIELDS == ["name"]
    assert User._meta.get_field("email").unique
    assert not User._meta.get_field("name").blank
    names = {f.name for f in User._meta.get_fields()}
    assert not {"username", "first_name", "last_name"} & names


# ---- normalization --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("alice@example.com", "alice@example.com"),
        ("  Alice@Example.COM \n", "alice@example.com"),
        ("ALICE@EXAMPLE.COM", "alice@example.com"),
        ("\t\u00a0Alice@Example.com\r\n", "alice@example.com"),
        # Provider-specific rewriting is forbidden: dots and +tags are preserved.
        ("a.l.i.c.e+news@Gmail.com", "a.l.i.c.e+news@gmail.com"),
    ],
)
def test_email_normalization(raw, normalized):
    assert User.objects.normalize_email(raw) == normalized


def test_normalization_matches_allauth_storage_form():
    from allauth.account.models import EmailAddress

    raw = "MiXeD@Example.COM"
    assert User.objects.normalize_email(raw) == EmailAddress(email=raw).email.lower()


@pytest.mark.django_db
def test_create_user_normalizes_email_and_stores_display_name():
    user = User.objects.create_user(email="  Alice@Example.COM ", name="  Alice Smith ", password="s3cret-Pass-phrase")
    user.refresh_from_db()
    assert user.email == "alice@example.com"
    assert user.name == "Alice Smith"
    assert user.get_full_name() == user.get_short_name() == "Alice Smith"
    assert str(user) == user.get_username() == "alice@example.com"
    assert isinstance(user.pk, uuid.UUID)


@pytest.mark.django_db
def test_direct_save_normalizes_too():
    user = User(email=" Bob@Example.com ", name=" Bob ")
    user.set_password("another-S3cret-phrase")
    user.save()
    user.refresh_from_db()
    assert (user.email, user.name) == ("bob@example.com", "Bob")


@pytest.mark.django_db
def test_create_user_requires_email_and_name():
    with pytest.raises(ValueError, match="email"):
        User.objects.create_user(email="  ", name="x")
    with pytest.raises(ValueError, match="display name"):
        User.objects.create_user(email="a@example.com", name="   ")
    with pytest.raises(ValueError, match="display name"):
        User.objects.create_user(email="a@example.com")


@pytest.mark.django_db
def test_create_superuser_sets_flags_and_rejects_contradictions():
    root = User.objects.create_superuser(email="Root@Example.com", name="Root", password="r00t-S3cret-phrase")
    assert (root.email, root.is_staff, root.is_superuser, root.is_active) == ("root@example.com", True, True, True)
    with pytest.raises(ValueError, match="is_staff"):
        User.objects.create_superuser(email="x@example.com", name="X", is_staff=False)
    with pytest.raises(ValueError, match="is_superuser"):
        User.objects.create_superuser(email="y@example.com", name="Y", is_superuser=False)


# ---- uniqueness (application and database) --------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("duplicate", ["alice@example.com", "ALICE@example.com", "  Alice@EXAMPLE.com  "])
def test_normalized_email_is_unique(duplicate):
    User.objects.create_user(email="alice@example.com", name="Alice")
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.create_user(email=duplicate, name="Other")


@pytest.mark.django_db
def test_model_validation_reports_a_duplicate_email_in_any_case():
    User.objects.create_user(email="alice@example.com", name="Alice")
    candidate = User(email="ALICE@Example.com", name="Other")
    with pytest.raises(ValidationError) as excinfo:
        candidate.full_clean(exclude=["password"])
    assert "email" in excinfo.value.message_dict


@pytest.mark.django_db
@pytest.mark.parametrize("email", ["Upper@example.com", " padded@example.com", "", "   ", "\tpadded@example.com\n"])
def test_database_rejects_non_canonical_email_even_when_the_model_is_bypassed(email):
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.bulk_create([User(email=email, name="Bypass", password="!")])


# Every character Python's strip() removes: PostgreSQL's TRIM only removes spaces, so the checks must agree.
WHITESPACE = [chr(c) for c in range(sys.maxunicode + 1) if chr(c).isspace()]


def test_the_whitespace_set_is_what_strip_removes():
    assert all((ch + "x" + ch).strip() == "x" for ch in WHITESPACE)
    assert len(WHITESPACE) >= 25


@pytest.mark.django_db
@pytest.mark.parametrize("ch", WHITESPACE, ids=lambda ch: f"U+{ord(ch):04X}")
def test_database_rejects_any_whitespace_padding_python_would_strip(ch):
    for email, name in [(f"{ch}pad@example.com", "Pad"), (f"pad@example.com{ch}", "Pad"), ("pad@example.com", f"{ch}Pad"), ("pad@example.com", f"Pad{ch}")]:
        with pytest.raises(IntegrityError), transaction.atomic():
            User.objects.bulk_create([User(email=email, name=name, password="!")])


@pytest.mark.django_db
@pytest.mark.parametrize("ch", WHITESPACE, ids=lambda ch: f"U+{ord(ch):04X}")
def test_save_normalizes_whitespace_so_the_database_accepts_it(ch):
    user = User.objects.create_user(email=f"{ch}pad@example.com{ch}", name=f"{ch}Pad{ch}")
    user.refresh_from_db()
    assert (user.email, user.name) == ("pad@example.com", "Pad")


@pytest.mark.django_db
@pytest.mark.parametrize("name", ["", " leading", "trailing ", "\tTabbed"])
def test_database_rejects_blank_or_untrimmed_display_name(name):
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.bulk_create([User(email="n@example.com", name=name, password="!")])


@pytest.mark.django_db
def test_database_rejects_case_variant_duplicates_when_the_model_is_bypassed():
    User.objects.create_user(email="alice@example.com", name="Alice")
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.bulk_create([User(email="alice@example.com", name="Dup", password="!")])
    with pytest.raises(IntegrityError), transaction.atomic():
        User.objects.bulk_create([User(email="ALICE@example.com", name="Dup", password="!")])


# ---- Django authentication ------------------------------------------------------------------


@pytest.mark.django_db
def test_password_is_hashed_by_django_and_authenticates_by_email_in_any_case():
    password = "correct-Horse-battery-9"
    user = User.objects.create_user(email="alice@example.com", name="Alice", password=password)
    assert user.password != password and user.password.startswith(("pbkdf2_", "argon2", "scrypt", "bcrypt"))
    assert user.check_password(password)
    assert authenticate(email="alice@example.com", password=password) == user
    assert authenticate(username="ALICE@Example.com", password=password) == user
    assert authenticate(username="alice@example.com", password="wrong") is None


@pytest.mark.django_db
def test_disabled_user_cannot_authenticate():
    password = "correct-Horse-battery-9"
    user = User.objects.create_user(email="alice@example.com", name="Alice", password=password)
    user.is_active = False
    user.save()
    assert authenticate(username="alice@example.com", password=password) is None


@pytest.mark.django_db
def test_user_without_password_has_an_unusable_one():
    user = User.objects.create_user(email="social@example.com", name="Social")
    assert not user.has_usable_password()
    assert authenticate(username="social@example.com", password="") is None

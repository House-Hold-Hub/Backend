"""Email verification and provider identity come from django-allauth, never from User columns."""

import pytest
from allauth.account.adapter import get_adapter
from allauth.account.auth_backends import AuthenticationBackend
from allauth.account.models import EmailAddress, EmailConfirmationHMAC
from allauth.account.utils import filter_users_by_email, user_email
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.cookie import CookieStorage
from django.core.management import call_command
from django.test import RequestFactory

User = get_user_model()
PASSWORD = "correct-Horse-battery-9"

pytestmark = pytest.mark.django_db


def test_django_system_checks_pass_with_the_allauth_configuration():
    call_command("check")


# ---- verified-email state derived from EmailAddress -----------------------------------------


def test_new_account_without_an_email_record_is_unverified():
    assert User.objects.create_user(email="a@example.com", name="A").is_email_verified is False


def test_unverified_record_is_unverified(make_user):
    assert make_user("a@example.com", verified=False).is_email_verified is False


def test_verified_record_for_the_account_email_is_verified(make_user):
    assert make_user("a@example.com", verified=True).is_email_verified is True


def test_state_follows_the_allauth_record_with_no_copy_on_the_user(make_user):
    user = make_user("a@example.com", verified=False)
    EmailAddress.objects.filter(user=user).update(verified=True)
    assert User.objects.get(pk=user.pk).is_email_verified is True
    EmailAddress.objects.filter(user=user).update(verified=False)
    assert User.objects.get(pk=user.pk).is_email_verified is False


def test_verified_secondary_address_does_not_count(make_user):
    user = make_user("a@example.com", verified=False)
    EmailAddress.objects.create(user=user, email="b@example.com", verified=True)
    assert user.is_email_verified is False


def test_verification_belongs_to_the_account_that_proved_the_address(make_user):
    other = make_user("b@example.com", verified=True)
    user = User.objects.create_user(email="a@example.com", name="A")
    assert user.is_email_verified is False
    assert other.is_email_verified is True


def test_changing_the_account_email_requires_a_new_verified_record(make_user):
    user = make_user("a@example.com", verified=True)
    user.email = "New@Example.com"
    user.save()
    assert user.is_email_verified is False
    EmailAddress.objects.create(user=user, email=user.email, verified=True)
    assert user.is_email_verified is True


def test_allauth_confirmation_flow_verifies_the_account():
    user = User.objects.create_user(email="Alice@Example.com", name="Alice", password=PASSWORD)
    address = EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=False)
    assert user.is_email_verified is False
    request = RequestFactory().post("/")
    request.user = user
    request._messages = CookieStorage(request)  # type: ignore[attr-defined]  # allauth reports the confirmation as a message
    confirmed = EmailConfirmationHMAC(address).confirm(request)
    assert confirmed is not None
    user = User.objects.get(pk=user.pk)
    assert user.is_email_verified is True
    assert EmailAddress.objects.get_primary(user).verified is True
    assert has_no_verification_column(user)


def has_no_verification_column(user):
    return not [f for f in user._meta.get_fields() if "verif" in f.name]


def test_trusted_provider_verified_email_is_honoured_through_the_allauth_record():
    # A social sign-in stores the provider-verified address as a verified EmailAddress.
    user = User.objects.create_user(email="g@example.com", name="G")
    EmailAddress.objects.create(user=user, email="g@example.com", primary=True, verified=True)
    SocialAccount.objects.create(user=user, provider="google", uid="1234567890", extra_data={})
    assert user.is_email_verified is True


# ---- provider identity through SocialAccount -------------------------------------------------


def test_provider_identity_is_a_socialaccount_not_a_user_column():
    user = User.objects.create_user(email="g@example.com", name="G")
    SocialAccount.objects.create(user=user, provider="google", uid="1234567890", extra_data={})
    assert user.socialaccount_set.get().provider == "google"
    assert not [f for f in user._meta.get_fields() if "google" in f.name]


# ---- identity lookups agree with allauth ------------------------------------------------------


def test_allauth_finds_the_user_by_email_in_any_case():
    user = User.objects.create_user(email="Alice@Example.com", name="Alice")
    assert list(filter_users_by_email("ALICE@example.COM")) == [user]


def test_allauth_authentication_backend_logs_in_by_email_in_any_case():
    user = User.objects.create_user(email="alice@example.com", name="Alice", password=PASSWORD)
    backend = AuthenticationBackend()
    assert backend.authenticate(None, email="ALICE@Example.com", password=PASSWORD) == user
    assert backend.authenticate(None, email="alice@example.com", password="wrong") is None


def test_allauth_adapter_builds_and_saves_a_user_without_username_fields():
    adapter = get_adapter()
    request = RequestFactory().post("/")
    user = adapter.new_user(request)

    class Form:
        cleaned_data = {"email": "Signup@Example.com", "password1": PASSWORD}

    adapter.save_user(request, user, Form(), commit=False)
    user.name = "Signup"
    user.save()
    user.refresh_from_db()
    assert user_email(user) == user.email == "signup@example.com"
    assert user.check_password(PASSWORD)


def test_allauth_does_not_treat_the_missing_username_field_as_an_error():
    user = User.objects.create_user(email="a@example.com", name="A")
    assert get_adapter().get_user_search_fields() == ["email"]
    assert user.get_username() == "a@example.com"

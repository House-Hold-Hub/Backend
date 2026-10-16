import pytest
from django.contrib.admin.sites import site
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()
pytestmark = pytest.mark.django_db


@pytest.fixture
def admin_client(client, make_user):
    admin = make_user("admin@example.com", is_staff=True, is_superuser=True)
    client.force_login(admin)
    return client


def test_user_is_registered_in_the_admin():
    assert User in site._registry


def test_changelist_shows_users_with_the_allauth_verification_state(admin_client, make_user):
    make_user("verified@example.com", verified=True)
    make_user("pending@example.com", verified=False)
    response = admin_client.get(reverse("admin:accounts_user_changelist"))
    assert response.status_code == 200
    rows = {u.email: u._email_verified for u in response.context["cl"].result_list}
    assert rows == {"admin@example.com": True, "verified@example.com": True, "pending@example.com": False}


def test_change_page_renders_and_does_not_edit_verification(admin_client, make_user):
    user = make_user("pending@example.com", verified=False)
    response = admin_client.get(reverse("admin:accounts_user_change", args=[user.pk]))
    assert response.status_code == 200
    assert "email_verified" not in response.context["adminform"].form.fields


def test_admin_can_create_a_user_with_a_normalized_email(admin_client):
    response = admin_client.post(
        reverse("admin:accounts_user_add"),
        {"email": "New@Example.COM", "name": "New", "password1": "correct-Horse-battery-9", "password2": "correct-Horse-battery-9"},
    )
    assert response.status_code == 302
    user = User.objects.get(email="new@example.com")
    assert user.name == "New" and not user.is_email_verified

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret")

import pytest  # noqa: E402


@pytest.fixture
def make_user(db):
    """Create a saved user; verified users get the allauth ``EmailAddress`` that marks them verified."""
    from allauth.account.models import EmailAddress
    from django.contrib.auth import get_user_model

    counter = iter(range(1, 10_000))

    def make(email=None, name="Member", *, verified=True, **extra):
        email = email or f"member{next(counter)}@example.com"
        user = get_user_model().objects.create_user(email=email, name=name, **extra)
        EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=verified)
        return user

    return make

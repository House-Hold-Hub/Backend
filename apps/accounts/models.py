import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom user model skeleton (UUID primary key).

    Passwords use Django's facilities; verified email and provider identities
    use django-allauth (EmailAddress / SocialAccount). The remaining fields
    are completed in Backend#2.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

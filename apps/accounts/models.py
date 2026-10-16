import uuid

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower

# Every character Python's ``str.strip()`` treats as whitespace. PostgreSQL's TRIM only removes spaces,
# so the database checks match this class explicitly to agree with ``normalize_email`` on writes that
# bypass ``save()`` (bulk_create, QuerySet.update, raw SQL). PostgreSQL ARE syntax.
WHITESPACE_CLASS = r"[[:space:]\u001c-\u001f\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]"


class UserManager(BaseUserManager["User"]):
    """Manager for an email-identified user (``USERNAME_FIELD = "email"``)."""

    use_in_migrations = True

    @classmethod
    def normalize_email(cls, email):
        """Canonical form of an address: surrounding whitespace removed, lower case.

        This is the normalization django-allauth applies to the addresses it stores
        (``EmailAddress.email``), so both sides compare equal. No provider-specific rewriting
        (Gmail dots, ``+tag`` suffixes) is performed (PRD Identity, security model).
        """
        return (email or "").strip().lower()

    def get_by_natural_key(self, username):
        # Authentication looks users up by the (normalized) email: "Alice@Example.com" logs in.
        return super().get_by_natural_key(self.normalize_email(username))

    def _create_user(self, email, password, **extra_fields):
        email = self.normalize_email(email)
        if not email:
            raise ValueError("An email address is required.")
        if not (extra_fields.get("name") or "").strip():
            raise ValueError("A display name is required.")
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields["is_staff"] is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields["is_superuser"] is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """HouseHoldHub authentication principal (ADR-010, ADR-011, domain model "User").

    - UUID primary key; the normalized email is the unique login identity.
    - ``name`` is the display name shown to household members.
    - Passwords are Django's (``AbstractUser.password``, hashed by Django); there is no bespoke
      password field and no provider-specific ``google_id``: provider identities are
      django-allauth ``SocialAccount`` rows.
    - Email verification is *not* stored here: it is derived from django-allauth's
      ``EmailAddress`` (``is_email_verified``), so no duplicate flag can drift.
    - ``is_active`` is the disabled/enabled lifecycle state; a disabled user cannot authenticate.

    ``username``, ``first_name`` and ``last_name`` of ``AbstractUser`` are removed: the identity
    is the email and the display name is the single ``name`` field.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None  # type: ignore[assignment]
    first_name = None  # type: ignore[assignment]
    last_name = None  # type: ignore[assignment]
    email = models.EmailField(
        "email address",
        max_length=254,
        unique=True,
        error_messages={"unique": "A user with that email address already exists."},
    )
    name = models.CharField("display name", max_length=150)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    objects = UserManager()  # type: ignore[assignment,misc]

    class Meta(AbstractUser.Meta):
        constraints = [
            # Database-level guarantee behind the unique index: only canonical addresses can be
            # stored, so uniqueness is case-insensitive even for writes that bypass the model.
            models.CheckConstraint(
                condition=Q(email=Lower("email")) & ~Q(email="") & ~Q(email__regex=WHITESPACE_CLASS),
                name="accounts_user_email_normalized",
            ),
            models.CheckConstraint(
                condition=~Q(name="") & ~Q(name__regex=f"^{WHITESPACE_CLASS}|{WHITESPACE_CLASS}$"),
                name="accounts_user_name_not_blank",
            ),
        ]

    def save(self, *args, **kwargs):
        self.email = type(self).objects.normalize_email(self.email)
        self.name = (self.name or "").strip()
        super().save(*args, **kwargs)

    def clean(self):
        super().clean()  # normalizes the email through the manager
        self.name = (self.name or "").strip()

    def get_full_name(self):
        return self.name

    def get_short_name(self):
        return self.name

    @property
    def is_email_verified(self) -> bool:
        """Whether the account email is verified, as recorded by django-allauth.

        True only when an ``EmailAddress`` row that is verified exists *for this account's current
        email*. A verified secondary address does not count, and no application flag is read.
        """
        from allauth.account.models import EmailAddress

        if not self.email:
            return False
        return EmailAddress.objects.filter(user_id=self.pk, email=self.email, verified=True).exists()

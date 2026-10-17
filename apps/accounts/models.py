import uuid

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.contrib.sessions.base_session import AbstractBaseSession
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
    - ``is_active`` is the disabled/enabled lifecycle state; a disabled user cannot authenticate, and
      every change of it (disable or restoration) revokes all of the account's sessions (``Session``).

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


class Session(AbstractBaseSession):
    """A database-backed Django session that is also the indexed user-session registry (ADR-011).

    ``user`` is written by ``apps.accounts.sessions.SessionStore`` from the authenticated user id in
    the payload, in the same statement that stores the payload, so ownership cannot drift from the
    session it describes. Revocation deletes rows by this indexed column and never decodes or scans
    ``session_data``. Anonymous sessions have no owner.

    Changing ``User.is_active`` (disable or restoration) deletes every session of the account in the
    database itself (trigger from migration 0003), whichever way the row is written. Deleting a user
    deletes its sessions.

    No device-management view or activity tracking reads this table (ADR-011, PRD Identity).
    """

    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name="+")

    @classmethod
    def get_session_store_class(cls):
        from .sessions import SessionStore

        return SessionStore


class EmailVerificationBearer(models.Model):
    """A one-time bearer proving ownership of an account's initial email (ADR-016 "One-time bearer credentials").

    The bearer itself is sent only in the email's frontend URI fragment; only its SHA-256 digest is stored.
    At most one bearer per account is usable: issuing a new one (signup, ``resendEmailVerification``) marks
    the previous one ``superseded_at`` (rotation). ``email`` is the address the bearer was issued for, so a
    bearer never verifies an address the account no longer has. ``verifyEmail`` sets ``consumed_at``
    atomically with marking the allauth ``EmailAddress`` verified (``verification.verify_initial_email``).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="+")
    email = models.EmailField(max_length=254)
    digest = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    superseded_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user"],
                condition=Q(superseded_at__isnull=True, consumed_at__isnull=True),
                name="accounts_one_usable_email_verification_bearer",
            ),
        ]

    def __str__(self):
        return f"EmailVerificationBearer({self.id})"

    def is_usable(self, now) -> bool:
        return self.superseded_at is None and self.consumed_at is None and self.expires_at > now


class PrimaryEmailChange(models.Model):
    """A pending primary-email change and its one-time bearer (ADR-011, ADR-016, Backend#35).

    Kept apart from ``EmailVerificationBearer``: a change bearer is never accepted by ``verifyEmail`` and an
    initial-verification bearer never completes a change. The bearer is sent only in the URI fragment of
    an email to ``new_email``; only its SHA-256 digest is stored. At most one change per account is usable:
    a new request supersedes the previous one. The account's current email stays in effect until
    ``verifyPrimaryEmailChange`` consumes the row, in the same transaction that makes ``new_email`` the
    verified primary address, rotates the current session and revokes the others. The pending address is
    not an allauth ``EmailAddress`` until then, so requesting a change never reserves an address.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="+")
    new_email = models.EmailField(max_length=254)
    digest = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    superseded_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user"],
                condition=Q(superseded_at__isnull=True, consumed_at__isnull=True),
                name="accounts_one_usable_primary_email_change",
            ),
        ]

    def __str__(self):
        return f"PrimaryEmailChange({self.id})"

    def is_usable(self, now) -> bool:
        return self.superseded_at is None and self.consumed_at is None and self.expires_at > now

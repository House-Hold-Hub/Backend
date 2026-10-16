"""Complete the User for email identity (Backend#6, ADR-010, ADR-011).

The initial migration is kept as is. This one makes the normalized email the unique login identity,
adds the display name, drops ``username``/``first_name``/``last_name`` and adds database
constraints that keep the stored address canonical (and therefore case-insensitively unique).

Existing rows are normalized before the constraints are added, and so are the django-allauth
``EmailAddress`` rows of those users: verification is matched on the account's current email, so
leaving an allauth row in its old spelling would silently turn a verified account into an unverified one. Rows that cannot be reconciled
without guessing (a blank address, or two addresses that differ only in case or whitespace) stop
the migration with an explicit message instead of being merged or altered.
"""

import django.db.models.functions.text
from django.db import migrations, models
from django.db.migrations.exceptions import IrreversibleError

import apps.accounts.models

# Frozen copy of apps.accounts.models.WHITESPACE_CLASS (PostgreSQL ARE).
WHITESPACE = r"[[:space:]\u001c-\u001f\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]"


def _normalize(email):
    return (email or "").strip().lower()


def _normalize_email_addresses(apps, db):
    """Bring allauth's rows to the canonical spelling; refuse (never merge) when that would collide."""
    EmailAddress = apps.get_model("account", "EmailAddress")
    rows = list(EmailAddress.objects.using(db).order_by("pk"))
    per_user, verified = {}, {}
    for row in rows:
        email = _normalize(row.email)
        if (row.user_id, email) in per_user:
            raise RuntimeError(
                f"account.EmailAddress {row.pk} and {per_user[(row.user_id, email)]} of user {row.user_id} "
                f"are the same address after normalization ({email!r}); resolve the duplicate before migrating."
            )
        per_user[(row.user_id, email)] = row.pk
        if row.verified:
            if email in verified and verified[email] != row.user_id:
                raise RuntimeError(
                    f"account.EmailAddress {row.pk}: {email!r} is verified for two users after normalization; "
                    "resolve the duplicate before migrating."
                )
            verified[email] = row.user_id
    for row in rows:
        email = _normalize(row.email)
        if email != row.email:
            EmailAddress.objects.using(db).filter(pk=row.pk).update(email=email)


def normalize_existing_users(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    db = schema_editor.connection.alias
    _normalize_email_addresses(apps, db)
    seen = {}
    for user in User.objects.using(db).order_by("date_joined", "pk").iterator():
        email = _normalize(user.email)
        if not email:
            raise RuntimeError(f"accounts.User {user.pk} has no email address; resolve it before migrating.")
        if email in seen:
            raise RuntimeError(
                f"accounts.User {user.pk} and {seen[email]} share the normalized email {email!r}; "
                "resolve the duplicate before migrating."
            )
        seen[email] = user.pk
        name = f"{user.first_name} {user.last_name}".strip() or email.partition("@")[0]
        User.objects.using(db).filter(pk=user.pk).update(email=email, name=name[:150].strip())


def refuse_reverse_with_users(apps, schema_editor):
    """The removed username/first_name/last_name values cannot be recreated, so refuse with data present."""
    User = apps.get_model("accounts", "User")
    if User.objects.using(schema_editor.connection.alias).exists():
        raise IrreversibleError(
            "accounts.0002_email_identity drops username, first_name and last_name; it can only be reversed "
            "while the user table is empty."
        )


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
        ("account", "0001_initial"),
    ]

    operations = [
        migrations.AlterModelManagers(
            name="user",
            managers=[
                ("objects", apps.accounts.models.UserManager()),
            ],
        ),
        migrations.AddField(
            model_name="user",
            name="name",
            field=models.CharField(default="", max_length=150, verbose_name="display name"),
            preserve_default=False,
        ),
        migrations.RunPython(normalize_existing_users, migrations.RunPython.noop),
        migrations.RemoveField(model_name="user", name="first_name"),
        migrations.RemoveField(model_name="user", name="last_name"),
        migrations.RemoveField(model_name="user", name="username"),
        migrations.AlterField(
            model_name="user",
            name="email",
            field=models.EmailField(
                error_messages={"unique": "A user with that email address already exists."},
                max_length=254,
                unique=True,
                verbose_name="email address",
            ),
        ),
        migrations.AddConstraint(
            model_name="user",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("email", django.db.models.functions.text.Lower("email")),
                    models.Q(("email", ""), _negated=True),
                    models.Q(("email__regex", WHITESPACE), _negated=True),
                ),
                name="accounts_user_email_normalized",
            ),
        ),
        migrations.AddConstraint(
            model_name="user",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("name", ""), _negated=True),
                    models.Q(("name__regex", f"^{WHITESPACE}|{WHITESPACE}$"), _negated=True),
                ),
                name="accounts_user_name_not_blank",
            ),
        ),
        # Last forward, therefore first when unapplying: before any column is recreated.
        migrations.RunPython(migrations.RunPython.noop, refuse_reverse_with_users),
    ]

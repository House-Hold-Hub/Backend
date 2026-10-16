"""Complete the User for email identity (Backend#6, ADR-010, ADR-011).

The initial migration is kept as is. This one makes the normalized email the unique login identity,
adds the display name, drops ``username``/``first_name``/``last_name`` and adds database
constraints that keep the stored address canonical (and therefore case-insensitively unique).

Existing rows are normalized before the constraints are added. Rows that cannot be reconciled
without guessing (a blank address, or two addresses that differ only in case or whitespace) stop
the migration with an explicit message instead of being merged or altered.
"""

import django.db.models.functions.text
from django.db import migrations, models

import apps.accounts.models


def _normalize(email):
    return (email or "").strip().lower()


def normalize_existing_users(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    db = schema_editor.connection.alias
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


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
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
                    ("email", django.db.models.functions.text.Lower(django.db.models.functions.text.Trim("email"))),
                    models.Q(("email", ""), _negated=True),
                ),
                name="accounts_user_email_normalized",
            ),
        ),
        migrations.AddConstraint(
            model_name="user",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("name", django.db.models.functions.text.Trim("name")),
                    models.Q(("name", ""), _negated=True),
                ),
                name="accounts_user_name_not_blank",
            ),
        ),
    ]

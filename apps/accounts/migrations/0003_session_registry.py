"""accounts.Session: database-backed sessions with an indexed owner (the ADR-011 user-session registry).

The trigger revokes every session of an account whose ``is_active`` changes, on any write path
(``save()``, ``QuerySet.update``, admin, raw SQL): disabling revokes all sessions immediately and
restoration never revives one, so a restored account needs a fresh login.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

REVOKE_ON_LIFECYCLE_CHANGE = """
CREATE FUNCTION accounts_revoke_sessions_on_lifecycle_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM accounts_session WHERE user_id = NEW.id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER accounts_user_lifecycle_revokes_sessions
AFTER UPDATE OF is_active ON accounts_user
FOR EACH ROW WHEN (OLD.is_active IS DISTINCT FROM NEW.is_active)
EXECUTE FUNCTION accounts_revoke_sessions_on_lifecycle_change();
"""

DROP_REVOKE_ON_LIFECYCLE_CHANGE = """
DROP TRIGGER IF EXISTS accounts_user_lifecycle_revokes_sessions ON accounts_user;
DROP FUNCTION IF EXISTS accounts_revoke_sessions_on_lifecycle_change();
"""


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_email_identity'),
    ]

    operations = [
        migrations.CreateModel(
            name='Session',
            fields=[
                ('session_key', models.CharField(max_length=40, primary_key=True, serialize=False, verbose_name='session key')),
                ('session_data', models.TextField(verbose_name='session data')),
                ('expire_date', models.DateTimeField(db_index=True, verbose_name='expire date')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'session',
                'verbose_name_plural': 'sessions',
                'abstract': False,
            },
        ),
        migrations.RunSQL(REVOKE_ON_LIFECYCLE_CHANGE, DROP_REVOKE_ON_LIFECYCLE_CHANGE),
    ]

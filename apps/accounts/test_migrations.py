"""0002 completes the user on top of the preserved initial migration, including with existing rows."""

import pytest
from django.db import IntegrityError, connection
from django.db.migrations.exceptions import IrreversibleError
from django.db.migrations.executor import MigrationExecutor

INITIAL = [("accounts", "0001_initial")]
EMAIL_IDENTITY = [("accounts", "0002_email_identity")]


def _migrate(targets):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(targets)
    return MigrationExecutor(connection).loader.project_state(targets).apps


@pytest.fixture
def at_initial(transactional_db):
    apps = _migrate(INITIAL)
    try:
        yield apps
    finally:
        # Rows that made a migration fail (or legacy-shaped rows) must not leak into the next step.
        with connection.cursor() as cursor:
            cursor.execute("TRUNCATE accounts_user CASCADE")
        _migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())


def _account_apps():
    """Historical models of accounts@0001 together with allauth's EmailAddress (tables already exist)."""
    return MigrationExecutor(connection).loader.project_state(INITIAL + [("account", "0001_initial")]).apps


def _old_user(apps, **fields):
    defaults = {"password": "!", "username": fields.get("email", "u"), "email": "u@example.com"}
    return apps.get_model("accounts", "User").objects.create(**{**defaults, **fields})


@pytest.mark.django_db
def test_initial_migration_is_preserved():
    loader = MigrationExecutor(connection).loader
    names = sorted(name for app, name in loader.graph.nodes if app == "accounts")
    assert names[0] == "0001_initial"
    parents = {node.key for node in loader.graph.node_map[("accounts", "0002_email_identity")].parents}
    # allauth's EmailAddress rows are reconciled with the normalized emails, so its table must exist.
    assert parents == {("accounts", "0001_initial"), ("account", "0001_initial")}


@pytest.mark.django_db
def test_migration_is_in_sync_with_the_models():
    from django.core.management import call_command

    call_command("makemigrations", "--check", "--dry-run")


def test_existing_users_are_normalized_and_named(at_initial):
    Group = at_initial.get_model("auth", "Group")
    user = _old_user(at_initial, username="alice", email="  Alice@Example.COM ", first_name="Alice", last_name="Smith")
    nameless = _old_user(at_initial, username="bob", email="Bob@Example.com")
    user.groups.add(Group.objects.create(name="staff-like"))  # a row referencing the user while columns change

    apps = _migrate(EMAIL_IDENTITY)
    User = apps.get_model("accounts", "User")
    assert User.objects.get(pk=user.pk).email == "alice@example.com"
    assert User.objects.get(pk=user.pk).name == "Alice Smith"
    assert User.objects.get(pk=nameless.pk).name == "bob"  # local part when there was no name
    assert User.objects.get(pk=user.pk).groups.count() == 1
    assert {f.name for f in User._meta.get_fields()} >= {"name", "email"}
    assert not {"username", "first_name", "last_name"} & {f.name for f in User._meta.get_fields()}


def test_migrated_database_enforces_the_constraints(at_initial):
    _old_user(at_initial, username="alice", email="Alice@Example.COM")
    apps = _migrate(EMAIL_IDENTITY)
    User = apps.get_model("accounts", "User")
    with pytest.raises(IntegrityError):
        User.objects.create(email="alice@example.com", name="Dup", password="!")
    with pytest.raises(IntegrityError):
        User.objects.create(email="Other@Example.com", name="Mixed", password="!")


def test_case_variant_duplicates_stop_the_migration_without_changes(at_initial):
    first = _old_user(at_initial, username="one", email="dup@example.com")
    _old_user(at_initial, username="two", email="DUP@example.com")
    with pytest.raises(RuntimeError, match="share the normalized email"):
        _migrate(EMAIL_IDENTITY)
    # Atomic migration: nothing was applied, the rows are untouched.
    assert MigrationExecutor(connection).loader.applied_migrations.keys() >= set(INITIAL)
    assert ("accounts", "0002_email_identity") not in MigrationExecutor(connection).loader.applied_migrations
    assert at_initial.get_model("accounts", "User").objects.get(pk=first.pk).email == "dup@example.com"


def test_blank_email_stops_the_migration(at_initial):
    _old_user(at_initial, username="blank", email="")
    with pytest.raises(RuntimeError, match="no email address"):
        _migrate(EMAIL_IDENTITY)


def test_migration_applies_to_an_empty_table_and_back(at_initial):
    _migrate(EMAIL_IDENTITY)
    _migrate(INITIAL)
    _migrate(EMAIL_IDENTITY)


# ---- allauth rows follow the normalization (a verified account must stay verified) ----------------


def test_verified_accounts_stay_verified_when_their_email_is_normalized(at_initial):
    apps_with_allauth = _account_apps()
    EmailAddress = apps_with_allauth.get_model("account", "EmailAddress")
    padded = _old_user(at_initial, username="padded", email="  Alice@Example.COM ")
    cased = _old_user(at_initial, username="cased", email="Bob@Example.com")
    pending = _old_user(at_initial, username="pending", email="Carol@Example.com")
    EmailAddress.objects.create(user_id=padded.pk, email="  alice@example.com ", verified=True, primary=True)
    EmailAddress.objects.create(user_id=cased.pk, email="Bob@Example.COM", verified=True, primary=True)
    EmailAddress.objects.create(user_id=pending.pk, email="carol@example.com", verified=False, primary=True)

    _migrate(EMAIL_IDENTITY)

    from django.contrib.auth import get_user_model

    User = get_user_model()
    assert User.objects.get(pk=padded.pk).is_email_verified is True
    assert User.objects.get(pk=cased.pk).is_email_verified is True
    assert User.objects.get(pk=pending.pk).is_email_verified is False
    assert sorted(EmailAddress.objects.values_list("email", flat=True)) == [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
    ]


def test_email_addresses_colliding_after_normalization_stop_the_migration(at_initial):
    EmailAddress = _account_apps().get_model("account", "EmailAddress")
    user = _old_user(at_initial, username="one", email="one@example.com")
    EmailAddress.objects.create(user_id=user.pk, email="one@example.com", verified=True, primary=True)
    EmailAddress.objects.create(user_id=user.pk, email="One@Example.com", verified=False, primary=False)
    with pytest.raises(RuntimeError, match="same address after normalization"):
        _migrate(EMAIL_IDENTITY)


# ---- reversal ------------------------------------------------------------------------------------


def test_reversal_is_refused_while_users_exist(at_initial):
    from django.contrib.auth import get_user_model

    _migrate(EMAIL_IDENTITY)
    get_user_model().objects.create_user(email="a@example.com", name="A")
    with pytest.raises(IrreversibleError, match="only be reversed while the user table is empty"):
        _migrate(INITIAL)
    # Nothing was changed by the refused reversal.
    assert get_user_model().objects.filter(email="a@example.com").exists()

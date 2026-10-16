"""Racing writers cannot create two accounts for one normalized email (database-enforced)."""

import threading

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection

User = get_user_model()
VARIANTS = ["race@example.com", "RACE@example.com", "  Race@Example.COM ", "rAcE@eXaMpLe.com"]


def _race(workers):
    barrier = threading.Barrier(len(workers))
    outcomes: list[str] = [""] * len(workers)

    def run(index):
        try:
            barrier.wait(timeout=10)
            workers[index]()
            outcomes[index] = "created"
        except IntegrityError:
            outcomes[index] = "duplicate"
        except Exception as exc:  # pragma: no cover - surfaced by the assertion below
            outcomes[index] = repr(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    return outcomes


@pytest.mark.django_db(transaction=True)
def test_concurrent_signups_with_case_variants_of_one_email_create_exactly_one_user():
    def signup(i):
        return lambda: User.objects.create_user(email=VARIANTS[i % len(VARIANTS)], name=f"Racer {i}")

    workers = [signup(i) for i in range(8)]
    outcomes = _race(workers)
    assert sorted(outcomes) == ["created"] + ["duplicate"] * 7
    assert list(User.objects.values_list("email", flat=True)) == ["race@example.com"]


@pytest.mark.django_db(transaction=True)
def test_concurrent_signups_with_distinct_emails_all_succeed():
    workers = [(lambda i=i: User.objects.create_user(email=f"user{i}@example.com", name=f"U{i}")) for i in range(6)]
    assert _race(workers) == ["created"] * 6
    assert User.objects.count() == 6


@pytest.mark.django_db(transaction=True)
def test_concurrent_email_change_cannot_take_an_address_that_is_being_registered():
    owner = User.objects.create_user(email="owner@example.com", name="Owner")

    def register():
        User.objects.create_user(email="contested@example.com", name="New")

    def change():
        user = User.objects.get(pk=owner.pk)
        user.email = "Contested@Example.com"
        user.save()

    outcomes = _race([register, change])
    assert sorted(outcomes) == ["created", "duplicate"]
    assert User.objects.filter(email="contested@example.com").count() == 1

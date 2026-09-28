# HouseHoldHub Backend

Django backend scaffold for the HouseHoldHub MVP engineering foundation.

## Baseline

The repository targets the Documentation-owned Python 3.14 / Django 5.2 LTS baseline, with Django REST Framework, django-allauth and PostgreSQL as the approved backend technology families. Exact runtime and dependency selections are owned here by `.python-version`, the requirements manifests, and their compiled lockfiles.

The custom `users.User` model uses a UUID primary key and is configured through `AUTH_USER_MODEL` before any application migration is generated. The initial migration itself is deliberately left to the follow-up identity-model issue.

Same-origin frontend/API deployment is the default. No CORS layer is configured; a future cross-origin topology requires an explicit CORS and credential review.

## Development checks

Create a Python 3.14 virtual environment, install the development lockfile, then run:

```bash
python manage.py check
pytest
ruff check .
ruff format --check .
mypy .
```

Dependency locks are generated with `pip-tools` from `requirements.in` and `requirements-dev.in`.

This scaffold intentionally does not add DRF routing/permissions, Docker configuration, or GitHub Actions; those belong to subsequent M0 issues.

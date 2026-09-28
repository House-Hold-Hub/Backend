from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_uses_repository_python_runtime_and_runs_backend() -> None:
    python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert f"FROM python:{python_version}-slim" in dockerfile
    assert "COPY requirements.lock ." in dockerfile
    assert "python -m pip install --no-cache-dir -r requirements.lock" in dockerfile
    assert "USER householdhub" in dockerfile
    assert 'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]' in dockerfile


def test_local_runtime_example_documents_required_environment() -> None:
    runtime_env = (ROOT / ".env.example").read_text(encoding="utf-8")

    required_variables = {
        "DJANGO_SECRET_KEY",
        "DJANGO_DEBUG",
        "DJANGO_ALLOWED_HOSTS",
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_HOST",
        "POSTGRES_PORT",
    }

    for variable in required_variables:
        assert f"{variable}=" in runtime_env


def test_backend_repository_has_no_full_stack_compose_definition() -> None:
    compose_filenames = (
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    )

    assert all(not (ROOT / filename).exists() for filename in compose_filenames)

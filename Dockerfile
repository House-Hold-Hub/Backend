FROM python:3.14.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.lock .
RUN python -m pip install --no-cache-dir -r requirements.lock \
    && groupadd --system householdhub \
    && useradd --system --gid householdhub --create-home householdhub

COPY --chown=householdhub:householdhub . .

USER householdhub

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

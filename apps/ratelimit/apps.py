from django.apps import AppConfig


class RateLimitConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.ratelimit"
    label = "ratelimit"

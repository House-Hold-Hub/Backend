from __future__ import annotations

from django.urls import URLPattern, URLResolver

# Feature operations are introduced by their dedicated implementation issues.
# This empty route table intentionally keeps M0-B3 limited to the versioned API mount.
urlpatterns: list[URLPattern | URLResolver] = []

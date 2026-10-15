"""Routes served under ``/api/v1/``.

Each feature app contributes its operations here as it implements them, following the
Documentation-owned OpenAPI contract. ``manage.py check_api_contract`` fails if a route
here (or any API view mounted elsewhere) diverges from that contract.
"""

from django.urls import URLPattern, URLResolver

urlpatterns: list[URLPattern | URLResolver] = []

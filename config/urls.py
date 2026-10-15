"""Root URL configuration.

The API lives under the versioned ``/api/v1/`` prefix (the contract's server URL).
"""

from django.contrib import admin
from django.urls import include, path

handler404 = "apps.api.handlers.not_found"
handler500 = "apps.api.handlers.server_error"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("apps.api.urls")),
]

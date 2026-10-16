"""Test-only URLconf: the real routes plus a protected operation behind the verification gate."""

from django.urls import path

from apps.api.tests.support import ProtectedPost
from config.urls import urlpatterns as real_urlpatterns

urlpatterns = [*real_urlpatterns, path("api/v1/test-protected", ProtectedPost.as_view())]

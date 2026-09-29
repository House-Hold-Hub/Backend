from __future__ import annotations

from rest_framework.pagination import PageNumberPagination


class HouseholdHubPageNumberPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "limit"
    max_page_size = 100

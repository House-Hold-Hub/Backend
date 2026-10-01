from __future__ import annotations

from rest_framework.pagination import PageNumberPagination


class ApiPagination(PageNumberPagination):
    page_size_query_param = "limit"
    max_page_size = 100

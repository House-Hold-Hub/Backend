"""``page`` / ``limit`` pagination matching the contract's ``Page``, ``Limit`` and ``PageMeta``."""

from rest_framework.exceptions import ValidationError
from rest_framework.pagination import BasePagination
from rest_framework.response import Response

DEFAULT_PAGE = 1
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
META_FIELDS = ("page", "limit", "total")


def _positive_int(request, name, default, maximum=None):
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationError({name: ["Must be an integer."]}) from None
    if value < 1:
        raise ValidationError({name: ["Must be at least 1."]})
    if maximum is not None and value > maximum:
        raise ValidationError({name: [f"Must be at most {maximum}."]})
    return value


class PageLimitPagination(BasePagination):
    """Envelope ``{"data": [...], "meta": {"page", "limit", "total"}}``.

    Invalid ``page``/``limit`` values are rejected with 400 rather than silently clamped.
    A page past the end is an empty page (never 404, which means "outside household scope").
    """

    def paginate_queryset(self, queryset, request, view=None):
        self.page = _positive_int(request, "page", DEFAULT_PAGE)
        self.limit = _positive_int(request, "limit", DEFAULT_LIMIT, MAX_LIMIT)
        self.total = len(queryset) if isinstance(queryset, (list, tuple)) else queryset.count()
        start = (self.page - 1) * self.limit
        return list(queryset[start : start + self.limit])

    def get_paginated_response(self, data):
        meta = {"page": self.page, "limit": self.limit, "total": self.total}
        return Response({"data": data, "meta": meta})

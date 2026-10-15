"""JSON ``ErrorResponse`` for unmatched or failing requests under ``/api/``; Django defaults elsewhere."""

from django.http import JsonResponse
from django.views import defaults

from .errors import ErrorCode, error_body


def _is_api(request):
    return request.path.startswith("/api/")


def not_found(request, exception, template_name="404.html"):
    if _is_api(request):
        return JsonResponse(error_body(ErrorCode.NOT_FOUND, "Not found."), status=404)
    return defaults.page_not_found(request, exception, template_name)


def server_error(request, template_name="500.html"):
    if _is_api(request):
        return JsonResponse(error_body(ErrorCode.INTERNAL_ERROR, "Internal server error."), status=500)
    return defaults.server_error(request, template_name)

import json

from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

import jwt

from posthog.models.subscription import unsubscribe_using_token


@csrf_exempt
@require_POST
def unsubscribe(request: HttpRequest):
    try:
        body = json.loads(request.body)
        token = body.get("token")
    except (json.JSONDecodeError, AttributeError):
        token = None

    if not token:
        return JsonResponse({"success": False})

    try:
        unsubscribe_using_token(token)
    except jwt.DecodeError:
        return JsonResponse({"success": False})

    return JsonResponse({"success": True})

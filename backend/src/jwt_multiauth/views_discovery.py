"""``GET /methods/`` — the unauthenticated, deployment-static discovery endpoint
(``docs/CONTRACT.md`` §5).

Not claimed by any of the six ``views_*.py`` modules CONTRACT §5 names by auth method — it
belongs to no method in particular, so it gets its own module. A deviation recorded in
``docs/CONTRACT.md`` §11's register.

The response carries nothing user-specific (``docs/CLAUDE-CODE-GUIDE-APP-JWT-MULTIAUTH.md`` §1:
"nothing else in this app is cacheable, since everything else is per-request-sensitive auth
state") — the same body for every caller, which is exactly what makes
``appkit.mixins.CachedListMixin`` safe here and nowhere else in this package.
"""

from __future__ import annotations

from typing import Any

from appkit.mixins import CachedListMixin
from drf_spectacular.utils import extend_schema
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import conf, throttling
from jwt_multiauth.serializers import AuthMethodsResponseSerializer


class _AuthMethodsBase(generics.GenericAPIView[Any]):
    """Owns the actual payload construction as ``list()`` so ``CachedListMixin`` (which wraps
    ``list()`` via ``super()``) has something concrete to wrap — see the mixin's own docstring:
    it must precede this base in the MRO, never be mixed into a class that defines ``list()``
    itself.
    """

    serializer_class = AuthMethodsResponseSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = []  # noqa: RUF012

    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        two_factor = conf.get_setting("TWO_FACTOR")
        payload = {
            "allowed_auth_methods": conf.get_setting("ALLOWED_AUTH_METHODS"),
            "two_factor": {
                "policy": two_factor["POLICY"],
                "allowed_methods": two_factor["ALLOWED_METHODS"],
            },
        }
        return Response(payload)


@extend_schema(
    summary="List enabled authentication methods and the 2FA policy",
    description=(
        "Unauthenticated discovery endpoint — returns which login methods and 2FA policy this "
        "deployment has enabled. The same response for every caller; cached accordingly."
    ),
    responses={200: AuthMethodsResponseSerializer},
    tags=["jwt-multiauth"],
)
class AuthMethodsView(CachedListMixin, _AuthMethodsBase):
    cache_namespace = "jwt_multiauth.methods"
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.METHODS

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return self.list(request, *args, **kwargs)

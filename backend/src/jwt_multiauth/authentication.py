"""``JWTAuthentication`` — the DRF authentication class every ``IsAuthenticated`` view in this
package declares explicitly via its own ``authentication_classes``, never via a host's
``DEFAULT_AUTHENTICATION_CLASSES``.

Not named or specified anywhere in ``docs/CONTRACT.md`` — a real gap discovered while
implementing Phase 6: ``/password/change/`` is ``IsAuthenticated``, but nothing else in this
package turns a Bearer access token into ``request.user``. Recorded as a deviation in
``docs/CONTRACT.md`` §11 rather than left implicit.

Delegates every claim check to ``services.TokenService.verify_access_token`` (which already
enforces ``typ == "access"``, so a refresh or ``pending_2fa`` token presented here is rejected the
same as a garbage string) — this module owns zero cryptographic logic of its own, only the
HTTP-header-to-``request.user`` plumbing DRF expects from an authentication class.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from jwt_multiauth import tokens
from jwt_multiauth.services import TokenService

__all__ = ["JWTAuthentication"]


class JWTAuthentication(BaseAuthentication):
    """Reads ``Authorization: Bearer <access-token>``. Returns ``None`` (never raises) when the
    header is absent or doesn't start with ``Bearer `` — DRF's own contract for "this
    authenticator doesn't apply here", letting a later authenticator (or ``AllowAny``) decide.
    Raises ``AuthenticationFailed`` for a present-but-invalid token: expired, malformed, bad
    signature, wrong ``typ``, or a ``sub`` that no longer resolves to a user.
    """

    keyword = "Bearer"

    def authenticate(self, request: Request) -> tuple[Any, dict[str, Any]] | None:
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not header:
            return None

        parts = header.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            return None

        raw_token = parts[1]
        try:
            claims = TokenService.verify_access_token(raw_token)
        except tokens.TokenError as exc:
            raise AuthenticationFailed("Invalid or expired access token.") from exc

        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=claims["sub"])
        except (user_model.DoesNotExist, ValueError, TypeError) as exc:
            raise AuthenticationFailed("Invalid or expired access token.") from exc

        return user, claims

    def authenticate_header(self, request: Request) -> str:
        # DRF sets the response's WWW-Authenticate header to this value on a 401 it raises for
        # NotAuthenticated — without it, DRF falls back to a 403 instead, per its own docs.
        return self.keyword


class JWTAuthenticationScheme(OpenApiAuthenticationExtension):
    """Registers ``JWTAuthentication`` with drf-spectacular as a bearer scheme — without this,
    schema generation warns "could not resolve authenticator" and ``--fail-on-warn`` fails the
    build for every view that declares it.
    """

    target_class = "jwt_multiauth.authentication.JWTAuthentication"
    name = "jwtMultiauthBearerAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, str]:
        return {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}

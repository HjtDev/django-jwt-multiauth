"""Token lifecycle views: refresh, verify, logout, logout-all.

Implements the views backing ``urls.py``'s ``/token/refresh/``, ``/token/verify/``,
``/logout/``, ``/logout/all/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md`` §5.
``POST /token/refresh/`` is where refresh-token rotation and reuse detection surface at the HTTP
layer — a reused (already-rotated) refresh token revokes the whole session chain and emits
``refresh_reuse_detected``, never silently issuing a fresh pair. ``TokenService``
(``services.py``, Phase 3) does the actual rotation/verification work; this module only
translates HTTP <-> service calls.
"""

from __future__ import annotations

from typing import Any, cast

from appkit.net import client_ip
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import throttling, tokens
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.login_flow import clear_auth_cookies, read_refresh_token, refresh_response
from jwt_multiauth.models import AuthSession
from jwt_multiauth.serializers import (
    LogoutAllResponseSerializer,
    TokenRefreshResponseSerializer,
    TokenRefreshSerializer,
    TokenVerifyResponseSerializer,
    TokenVerifySerializer,
)
from jwt_multiauth.services import (
    InvalidRefreshToken,
    RefreshReuseDetected,
    RequestMeta,
    TokenService,
)
from jwt_multiauth.signals import user_logged_out


class TokenRefreshView(generics.GenericAPIView[Any]):
    """``POST /token/refresh/``. Reads the refresh token per ``REFRESH_COOKIE["TRANSPORT"]`` —
    the cookie under the default transport, the request body under ``"body"`` — never requires
    the caller's own ``Authorization`` header (this endpoint IS how a caller obtains a fresh
    access token once the old one has expired). A missing token, a malformed/expired token, a
    revoked-or-expired session, and a detected reuse (which also revokes the whole session chain
    and fires ``refresh_reuse_detected``) all map to the same ``401`` shape — the contract's own
    row for this endpoint lists no distinguishable client-facing cause.
    """

    serializer_class = TokenRefreshSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TOKEN_REFRESH

    @extend_schema(
        summary="Rotate a refresh token for a fresh access token",
        description=(
            "Reads the refresh token from the cookie (default transport) or the request body "
            "(REFRESH_COOKIE['TRANSPORT'] == 'body'). Re-sets the cookie on success. A replayed "
            "(already-rotated) refresh token revokes the whole session and fires "
            "refresh_reuse_detected."
        ),
        request=TokenRefreshSerializer,
        responses={
            200: TokenRefreshResponseSerializer,
            401: OpenApiResponse(description="Missing, invalid, expired, or reused refresh token."),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        raw_refresh_token = read_refresh_token(request)
        if raw_refresh_token is None:
            raise AuthenticationFailed({"code": "invalid_refresh_token"})

        request_meta: RequestMeta = {"ip": client_ip(request)}
        try:
            pair = TokenService.rotate_refresh(raw_refresh_token, request_meta=request_meta)
        except RefreshReuseDetected as exc:
            raise AuthenticationFailed({"code": "refresh_reuse_detected"}) from exc
        except InvalidRefreshToken as exc:
            raise AuthenticationFailed({"code": "invalid_refresh_token"}) from exc

        # remember_me isn't part of the refresh request itself — it's a property of the
        # underlying session, read off the row rotate_refresh just touched, so the re-set
        # cookie's max_age matches the session it belongs to rather than always the short default.
        remember_me = AuthSession.objects.only("remember_me").get(pk=pair.session_id).remember_me
        return refresh_response(pair, remember_me=remember_me)


class TokenVerifyView(generics.GenericAPIView[Any]):
    """``POST /token/verify/``. Lets another service validate a token it received — the token is
    a body param, never required to be the caller's own ``Authorization`` header, and no
    authentication is attempted at all. Always ``200``, valid or not: ``docs/CONTRACT.md`` §5's
    own row for this endpoint lists only the two ``valid`` outcomes, never a ``401``.
    """

    serializer_class = TokenVerifySerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = []  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TOKEN_VERIFY

    @extend_schema(
        summary="Verify an access token without authenticating as it",
        description=(
            "Always 200. Returns {valid: true, claims} for a live, correctly-signed access "
            "token, or {valid: false} for anything else — expired, malformed, wrong typ, or "
            "tampered."
        ),
        request=TokenVerifySerializer,
        responses={200: TokenVerifyResponseSerializer},
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            claims = TokenService.verify_access_token(serializer.validated_data["token"])
        except tokens.TokenError:
            return Response({"valid": False})
        return Response({"valid": True, "claims": claims})


class LogoutView(generics.GenericAPIView[Any]):
    """``POST /logout/``. Revokes the CALLER's own current session only — identified from the
    access token's own ``sid`` claim (``request.auth``, populated by ``JWTAuthentication``), never
    from a request body — and clears both auth cookies. This view is ``user_logged_out``'s sole
    emitter (``signals.py``).
    """

    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.LOGOUT

    @extend_schema(
        summary="Log out the caller's current session",
        request=None,
        responses={204: None},
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        # request.auth is the decoded access-token claims dict JWTAuthentication.authenticate()
        # returns as its second tuple element (authentication.py) — typed generically by DRF's
        # own stubs, hence the cast.
        claims = cast("dict[str, Any]", request.auth)
        session_id = claims["sid"]
        TokenService.revoke_session(session_id, reason="user_logout")
        user_logged_out.send(sender=AuthSession, user_id=request.user.pk, session_id=session_id)

        response = Response(status=204)
        clear_auth_cookies(response)
        return response


class LogoutAllView(generics.GenericAPIView[Any]):
    """``POST /logout/all/``. Revokes every session for the caller, including the one making this
    request.
    """

    serializer_class = LogoutAllResponseSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.LOGOUT_ALL

    @extend_schema(
        summary="Log out every session for the caller",
        responses={200: LogoutAllResponseSerializer},
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        revoked_count = TokenService.revoke_all_sessions(request.user, reason="user_logout")
        response = Response({"revoked_count": revoked_count})
        clear_auth_cookies(response)
        return response

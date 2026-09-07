"""Self-service session and trusted-device views: list/revoke own sessions, list/revoke own
trusted devices.

Phase 8 implements the views backing ``urls.py``'s ``/sessions/``, ``/sessions/{id}/``,
``/trusted-devices/``, ``/trusted-devices/{id}/`` routes (basePath ``/api/v1/auth``), per
``docs/CONTRACT.md`` §5/§11 item 2. Every queryset here is filtered to the caller's own rows at
the query level — never a raw lookup by id alone, which would let one authenticated user revoke
another's session by guessing an id. ``docs/CONTRACT.md`` §5's own review note picks ``404`` over
``403`` for this case: a ``403`` on another user's id would confirm the id exists at all. That
choice falls out of the queryset filter itself (``get_object()`` -> ``get_object_or_404()``
against an already-user-scoped queryset), not a separate ``has_object_permission`` check.
Revocation goes through ``TokenService.revoke_session``/``TwoFactorService.revoke_trusted_device``
(``services.py``), never a raw queryset ``.update()``/``.delete()``, so the revoked-session/
``session_revoked`` signal path always fires.
"""

from __future__ import annotations

from typing import Any

from appkit.pagination import DefaultPagination
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import throttling
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.models import AuthSession, TrustedDevice
from jwt_multiauth.serializers import AuthSessionSerializer, TrustedDeviceSerializer
from jwt_multiauth.services import TokenService, TwoFactorService


class SessionListView(generics.ListAPIView[Any]):
    """``GET /sessions/``. Lists the CALLER's own ``AuthSession`` rows only, filtered at the
    queryset level.
    """

    serializer_class = AuthSessionSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.SESSIONS_LIST
    pagination_class = DefaultPagination

    def get_queryset(self) -> Any:
        # Typed Any, matching every services.py signature's own `user: Any` — request.user's
        # `User | AnonymousUser` type is stricter than a raw FK filter's stub expects.
        user: Any = self.request.user
        return AuthSession.objects.filter(user=user).order_by("-created_at")

    @extend_schema(
        summary="List the caller's own sessions",
        responses={200: AuthSessionSerializer},
        tags=["jwt-multiauth"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)


class SessionRevokeView(generics.DestroyAPIView[Any]):
    """``DELETE /sessions/{id}/``. ``404``, never ``403``, for a session id that exists but isn't
    the caller's own — see this module's own docstring.
    """

    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.SESSIONS_REVOKE

    def get_queryset(self) -> Any:
        user: Any = self.request.user
        return AuthSession.objects.filter(user=user)

    def perform_destroy(self, instance: AuthSession) -> None:
        # Never instance.delete() — TokenService.revoke_session is what fires session_revoked.
        TokenService.revoke_session(str(instance.pk), reason="user_logout")

    @extend_schema(
        summary="Revoke one of the caller's own sessions",
        responses={
            204: None,
            404: OpenApiResponse(description="No such session, or it isn't the caller's own."),
        },
        tags=["jwt-multiauth"],
    )
    def delete(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return self.destroy(request, *args, **kwargs)


class TrustedDeviceListView(generics.ListAPIView[Any]):
    """``GET /trusted-devices/``. Lists the CALLER's own ``TrustedDevice`` rows only."""

    serializer_class = TrustedDeviceSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TRUSTED_DEVICES_LIST
    pagination_class = DefaultPagination

    def get_queryset(self) -> Any:
        user: Any = self.request.user
        return TrustedDevice.objects.filter(user=user).order_by("-created_at")

    @extend_schema(
        summary="List the caller's own trusted devices",
        responses={200: TrustedDeviceSerializer},
        tags=["jwt-multiauth"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)


class TrustedDeviceRevokeView(generics.DestroyAPIView[Any]):
    """``DELETE /trusted-devices/{id}/``. Same ownership-check pattern as
    ``SessionRevokeView`` — ``404``, never ``403``, for a device id that isn't the caller's own.
    """

    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TRUSTED_DEVICES_REVOKE

    def get_queryset(self) -> Any:
        user: Any = self.request.user
        return TrustedDevice.objects.filter(user=user)

    def perform_destroy(self, instance: TrustedDevice) -> None:
        TwoFactorService.revoke_trusted_device(instance)

    @extend_schema(
        summary="Revoke one of the caller's own trusted devices",
        responses={
            204: None,
            404: OpenApiResponse(
                description="No such trusted device, or it isn't the caller's own."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def delete(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return self.destroy(request, *args, **kwargs)

"""The admin DRF API — basePath ``/api/v1/admin/auth``.

Phase 8 implements the views backing ``urls_admin.py``'s routes per ``docs/CONTRACT.md`` §5:
session list/revoke, trusted-device list/revoke, login-attempt list, per-user security summary,
account unlock, and force-disable-2FA — every one gated by ``permissions.py``'s single admin
gate, resolved once from ``JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]``, plus a
``jwt_multiauth_admin_``-prefixed throttle scope (``throttling.py``) and a complete
``@extend_schema`` tagged ``["jwt-multiauth-admin"]``.

Force-disable-2FA is ``is_superuser``-only **unconditionally**, regardless of
``ADMIN_REQUIRES_SUPERUSER`` (``docs/CONTRACT.md`` §0 — the one admin gate that setting never
loosens). No response here ever exposes a password, a code, a ``code_hash``, a ``token_hash``, or
``secret_encrypted``.

Every admin list here is filterable ONLY via ``appkit.validation.validate_query_params`` (shape
validation) followed by ``appkit.validation.safe_filter_kwargs`` (the actual ``.filter()`` kwargs,
built from the allowlisted fields only) — never raw ``**request.GET`` into a ``filter()`` call,
which would let a caller traverse an unintended relation or lookup.
"""

from __future__ import annotations

from typing import Any

from appkit.pagination import DefaultPagination
from appkit.validation import safe_filter_kwargs, validate_query_params
from django.contrib.auth import get_user_model
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics
from rest_framework.generics import get_object_or_404
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import conf, throttling
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.models import AuthSession, LoginAttempt, TrustedDevice
from jwt_multiauth.permissions import IsAdmin, IsSuperUser
from jwt_multiauth.serializers import (
    AdminLoginAttemptFilterSerializer,
    AdminSessionFilterSerializer,
    AdminTrustedDeviceFilterSerializer,
    AdminUserSecurityResponseSerializer,
    AuthSessionSerializer,
    LoginAttemptSerializer,
    TrustedDeviceSerializer,
)
from jwt_multiauth.services import LockoutService, TokenService, TwoFactorService


class AdminSessionListView(generics.ListAPIView[Any]):
    """``GET /admin/sessions/``. Any user's rows, filterable by ``?user=``."""

    serializer_class = AuthSessionSerializer
    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_SESSIONS_LIST
    pagination_class = DefaultPagination

    def get_queryset(self) -> Any:
        validate_query_params(AdminSessionFilterSerializer, self.request.query_params)
        filter_kwargs = safe_filter_kwargs(self.request.query_params, allowed_fields=("user",))
        return AuthSession.objects.filter(**filter_kwargs).order_by("-created_at")

    @extend_schema(
        summary="List any user's sessions",
        responses={200: AuthSessionSerializer},
        tags=["jwt-multiauth-admin"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)


class AdminSessionRevokeView(generics.DestroyAPIView[Any]):
    """``DELETE /admin/sessions/{id}/``. Any user's session."""

    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_SESSIONS_REVOKE
    queryset = AuthSession.objects.all()

    def perform_destroy(self, instance: AuthSession) -> None:
        TokenService.revoke_session(str(instance.pk), reason="admin_revoked")

    @extend_schema(
        summary="Revoke any user's session",
        responses={204: None, 404: OpenApiResponse(description="No such session.")},
        tags=["jwt-multiauth-admin"],
    )
    def delete(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return self.destroy(request, *args, **kwargs)


class AdminTrustedDeviceListView(generics.ListAPIView[Any]):
    """``GET /admin/trusted-devices/``. Any user's rows, filterable by ``?user=`` —
    ``docs/CONTRACT.md`` §11 item 2 (the same gap item 18 flags for the self-service pair).
    """

    serializer_class = TrustedDeviceSerializer
    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_TRUSTED_DEVICES_LIST
    pagination_class = DefaultPagination

    def get_queryset(self) -> Any:
        validate_query_params(AdminTrustedDeviceFilterSerializer, self.request.query_params)
        filter_kwargs = safe_filter_kwargs(self.request.query_params, allowed_fields=("user",))
        return TrustedDevice.objects.filter(**filter_kwargs).order_by("-created_at")

    @extend_schema(
        summary="List any user's trusted devices",
        responses={200: TrustedDeviceSerializer},
        tags=["jwt-multiauth-admin"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)


class AdminTrustedDeviceRevokeView(generics.DestroyAPIView[Any]):
    """``DELETE /admin/trusted-devices/{id}/``. Any user's trusted device."""

    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_TRUSTED_DEVICES_REVOKE
    queryset = TrustedDevice.objects.all()

    def perform_destroy(self, instance: TrustedDevice) -> None:
        TwoFactorService.revoke_trusted_device(instance)

    @extend_schema(
        summary="Revoke any user's trusted device",
        responses={204: None, 404: OpenApiResponse(description="No such trusted device.")},
        tags=["jwt-multiauth-admin"],
    )
    def delete(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return self.destroy(request, *args, **kwargs)


class AdminLoginAttemptListView(generics.ListAPIView[Any]):
    """``GET /admin/login-attempts/``. Filterable by ``identifier``/``ip_address``/``user``/
    ``success``.
    """

    serializer_class = LoginAttemptSerializer
    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_LOGIN_ATTEMPTS_LIST
    pagination_class = DefaultPagination

    def get_queryset(self) -> Any:
        filters = validate_query_params(
            AdminLoginAttemptFilterSerializer, self.request.query_params
        )
        filter_kwargs = safe_filter_kwargs(
            self.request.query_params,
            allowed_fields=("identifier", "ip_address", "user", "success"),
        )
        if "success" in filter_kwargs:
            # safe_filter_kwargs passes an "exact"-lookup value through as the raw query string
            # (its own coercion only covers in/range/isnull) — Django's BooleanField.to_python
            # only accepts a narrow, case-sensitive literal set ("True"/"1"/"t", not "false"),
            # so a validator-accepted "?success=false" would otherwise 500 instead of filtering.
            # The serializer already validated this value; use ITS parsed bool instead of the
            # raw string.
            filter_kwargs["success"] = filters.validated_data["success"]
        return LoginAttempt.objects.filter(**filter_kwargs).order_by("-created_at")

    @extend_schema(
        summary="List login attempts",
        responses={200: LoginAttemptSerializer},
        tags=["jwt-multiauth-admin"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().get(request, *args, **kwargs)


class AdminUserSecurityView(generics.GenericAPIView[Any]):
    """``GET /admin/users/{id}/security/``. A read-only aggregate — no model of its own."""

    serializer_class = AdminUserSecurityResponseSerializer
    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_USER_SECURITY

    @extend_schema(
        summary="Get a user's 2FA status, active session count, and lock status",
        responses={200: AdminUserSecurityResponseSerializer},
        tags=["jwt-multiauth-admin"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        user = get_object_or_404(get_user_model().objects.all(), pk=kwargs["pk"])

        two_factor_status = {
            "policy": conf.get_setting("TWO_FACTOR")["POLICY"],
            "enrolled_methods": TwoFactorService.enrolled_methods(user),
            "eligible_methods": TwoFactorService.eligible_methods(
                user, used_primary_channel="password"
            ),
        }
        active_session_count = AuthSession.objects.filter(
            user=user, revoked_at__isnull=True, expires_at__gt=timezone.now()
        ).count()
        scope, lock_result = LockoutService.lock_status_for_user(user)
        lock_status = {
            "scope": scope,
            "locked": lock_result.locked if lock_result is not None else None,
            "until": lock_result.until if lock_result is not None else None,
        }

        return Response(
            {
                "two_factor_status": two_factor_status,
                "active_session_count": active_session_count,
                "lock_status": lock_status,
            }
        )


class AdminUserUnlockView(generics.GenericAPIView[Any]):
    """``POST /admin/users/{id}/unlock/``."""

    permission_classes = [IsAdmin]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_USER_UNLOCK

    @extend_schema(
        summary="Clear a user's lockout, across every identifier they could have typed",
        request=None,
        responses={204: None},
        tags=["jwt-multiauth-admin"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        user = get_object_or_404(get_user_model().objects.all(), pk=kwargs["pk"])
        LockoutService.unlock_user(user)
        return Response(status=204)


class AdminForceDisableTwoFactorView(generics.GenericAPIView[Any]):
    """``POST /admin/users/{id}/2fa/force-disable/``. ``is_superuser``-only, UNCONDITIONALLY —
    ``IsSuperUser``, never ``IsAdmin``, so ``ADMIN_REQUIRES_SUPERUSER`` can never loosen this one
    route (``docs/CONTRACT.md`` §0).
    """

    permission_classes = [IsSuperUser]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.ADMIN_TWO_FACTOR_FORCE_DISABLE

    @extend_schema(
        summary="Force-disable every 2FA method for a user",
        description="is_superuser-only, unconditionally — never satisfied by plain is_staff.",
        request=None,
        responses={204: None},
        tags=["jwt-multiauth-admin"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        user = get_object_or_404(get_user_model().objects.all(), pk=kwargs["pk"])
        TwoFactorService.admin_force_disable(user)
        return Response(status=204)

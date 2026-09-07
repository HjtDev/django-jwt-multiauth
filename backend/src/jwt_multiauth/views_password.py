"""Password-based self-service views: login, password change, password reset request/confirm.

Implements the views backing ``urls.py``'s ``/login/``, ``/password/change/``,
``/password/reset/request/``, ``/password/reset/confirm/`` routes (basePath ``/api/v1/auth``),
per ``docs/CONTRACT.md`` §5. Every identifier-taking endpoint here returns the same status, body
shape, and near-identical timing for an unknown identifier and a known identifier with a wrong
credential (this repo's ``CLAUDE.md`` rule 5) — ``POST /password/reset/request/`` always returns
``200`` regardless of whether the identifier resolves to a real, active account. ``PasswordService``
(``services.py``) does the actual authentication/reset work; this module only translates
HTTP <-> service calls.
"""

from __future__ import annotations

from typing import Any

from appkit.net import client_ip
from django.core.exceptions import ValidationError as DjangoValidationError
from drf_spectacular.utils import OpenApiResponse, PolymorphicProxySerializer, extend_schema
from rest_framework import generics
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import throttling
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.login_flow import login_response
from jwt_multiauth.serializers import (
    LoginPendingTwoFactorResponseSerializer,
    LoginRequestSerializer,
    LoginTokensResponseSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
)
from jwt_multiauth.services import ChallengeInvalid, LockoutService, PasswordService, RequestMeta

_LOGIN_RESPONSE = PolymorphicProxySerializer(
    component_name="LoginResponse",
    serializers=[LoginTokensResponseSerializer, LoginPendingTwoFactorResponseSerializer],
    resource_type_field_name=None,
)


class LoginView(generics.GenericAPIView[Any]):
    """``POST /login/``. Enumeration-resistant: an unknown identifier and a known identifier
    with a wrong password produce byte-for-byte the same status and body
    (``PasswordService.authenticate``'s dummy-hash path). A locked-out identifier is rejected
    BEFORE ``PasswordService.authenticate`` is ever called — a materially different failure
    (rate-limit state, not a credential secret; see ``services.LockoutService.is_locked``'s own
    docstring for why this is not itself a timing side-channel).

    ``authentication_classes`` carries ``JWTAuthentication`` even though this view is
    ``AllowAny`` and never reads ``request.user`` — without a registered authenticator, DRF's own
    ``APIView.handle_exception`` has no ``WWW-Authenticate`` header to attach and silently
    downgrades every ``AuthenticationFailed`` raised below from ``401`` to ``403`` instead
    (verified against a real request, not assumed from DRF's docs).
    """

    serializer_class = LoginRequestSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.LOGIN

    @extend_schema(
        summary="Log in with an identifier and password",
        description=(
            "Authenticates with a password. Returns real tokens directly when no second factor "
            "is required, or a pending_2fa handshake (`pending_token`, `eligible_methods`) when "
            "it is. An unknown identifier and a known identifier with a wrong password return "
            "the identical 401 body — this endpoint never reveals whether an identifier exists."
        ),
        request=LoginRequestSerializer,
        responses={
            200: _LOGIN_RESPONSE,
            401: OpenApiResponse(
                description="Invalid credentials, a locked account, or 2FA "
                "required with no eligible second factor."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["identifier"]
        password = serializer.validated_data["password"]
        remember_me = serializer.validated_data["remember_me"]

        ip = client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        if LockoutService.is_locked(identifier, ip=ip).locked:
            LockoutService.record_attempt(
                identifier,
                ip=ip,
                success=False,
                method="password",
                reason="locked",
                user_agent=user_agent,
            )
            raise AuthenticationFailed({"code": "account_locked"})

        user = PasswordService.authenticate(identifier, password)
        if user is None:
            LockoutService.record_attempt(
                identifier,
                ip=ip,
                success=False,
                method="password",
                reason="wrong_credential",
                user_agent=user_agent,
            )
            raise AuthenticationFailed({"code": "invalid_credentials"})

        LockoutService.record_attempt(
            identifier, ip=ip, success=True, method="password", user_agent=user_agent
        )

        request_meta: RequestMeta = {
            "ip": ip,
            "user_agent": user_agent,
            "device_label": "",
            "method": "password",
        }
        return login_response(
            user,
            request=request,
            request_meta=request_meta,
            remember_me=remember_me,
            created=False,
            used_primary_channel="password",
            primary_method="password",
        )


class PasswordChangeView(generics.GenericAPIView[Any]):
    """``POST /password/change/``. ``old_password`` is required even for an already-authenticated
    caller — a re-auth step for a sensitive action, not a plain profile edit. Revokes every
    session for the caller, including the one making this request — a subsequent refresh attempt
    with the now-superseded session fails, and the client must log in again to obtain a new one.
    """

    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.PASSWORD_CHANGE

    @extend_schema(
        summary="Change the authenticated user's password",
        description=(
            "Requires the current password. Revokes every session for this user, including the "
            "one making this request — the client must log in again afterward."
        ),
        request=PasswordChangeSerializer,
        responses={
            204: None,
            400: OpenApiResponse(
                description="Wrong old_password, or the new password failed a configured validator."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            PasswordService.change_password(
                request.user,
                serializer.validated_data["old_password"],
                serializer.validated_data["new_password"],
            )
        except DjangoValidationError as exc:
            # PasswordService.change_password raises a single ValidationError with code=
            # "invalid_old_password" for a wrong old_password; validate_password's own
            # ValidationError (a failed AUTH_PASSWORD_VALIDATORS check) is built from a plain
            # list of messages instead and carries no .code attribute at all — getattr, not
            # exc.code, or the validator-failure branch itself raises AttributeError.
            if getattr(exc, "code", None) == "invalid_old_password":
                raise ValidationError({"old_password": [str(m) for m in exc.messages]}) from exc
            raise ValidationError({"new_password": [str(m) for m in exc.messages]}) from exc
        return Response(status=204)


class PasswordResetRequestView(generics.GenericAPIView[Any]):
    """``POST /password/reset/request/``. Always ``200``, regardless of whether ``identifier``
    resolves to a real, active account — ``PasswordService.request_reset``'s own result is
    discarded entirely.
    """

    serializer_class = PasswordResetRequestSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = []  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.PASSWORD_RESET_REQUEST

    @extend_schema(
        summary="Request a password reset OTP challenge",
        description=(
            "Always returns 200, whether or not `identifier` resolves to a real account — this "
            "endpoint never reveals account existence."
        ),
        request=PasswordResetRequestSerializer,
        responses={200: OpenApiResponse(description="Always returned, unconditionally.")},
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        PasswordService.request_reset(serializer.validated_data["identifier"])
        return Response({})


class PasswordResetConfirmView(generics.GenericAPIView[Any]):
    """``POST /password/reset/confirm/``. An unresolved/expired/decoy ``challenge_id``, a wrong
    code, and a challenge that isn't ``purpose="password_reset"`` (including one that just
    auto-provisioned a brand-new account — see ``PasswordService.confirm_reset``'s own docstring)
    all produce the identical ``ChallengeInvalid`` -> ``400``.
    """

    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = []  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.PASSWORD_RESET_CONFIRM

    @extend_schema(
        summary="Confirm a password reset with an OTP code or magic-link token",
        description="Exactly one of `code`/`link_token` is required.",
        request=PasswordResetConfirmSerializer,
        responses={
            204: None,
            400: OpenApiResponse(
                description="Invalid/expired challenge, or "
                "the new password failed a configured validator."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            PasswordService.confirm_reset(
                data["challenge_id"],
                code=data.get("code"),
                link_token=data.get("link_token"),
                new_password=data["new_password"],
            )
        except ChallengeInvalid as exc:
            raise ValidationError({"code": "otp_challenge_invalid"}) from exc
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": [str(m) for m in exc.messages]}) from exc
        return Response(status=204)

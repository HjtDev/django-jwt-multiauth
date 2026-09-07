"""OTP-based self-service views: request, verify, resend.

Implements the views backing ``urls.py``'s ``/otp/request/``, ``/otp/verify/``,
``/otp/resend/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md`` §5. The magic-link
login variant is a form of ``POST /otp/verify/`` (a link token in place of a code), not a
separate route. ``POST /otp/request/`` for an unregistered identifier on a method NOT in
``USER_FIELDS.AUTO_PROVISION_METHODS`` returns a real-shaped decoy challenge rather than a
``404`` (this repo's ``CLAUDE.md`` rule 5) — never a persisted decoy row (``docs/CONTRACT.md``
§11 item 11, see ``models.py``). For a method IN that list, the same unregistered identifier
instead persists a REAL, ``user=None`` challenge (``docs/CONTRACT.md`` §11 item 19) —
identical response shape either way. ``OtpService`` (``services.py``) does the actual challenge
lifecycle; this module only translates HTTP <-> service calls.
"""

from __future__ import annotations

from typing import Any

from appkit.net import client_ip
from drf_spectacular.utils import OpenApiResponse, PolymorphicProxySerializer, extend_schema
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import conf, otp, throttling
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.login_flow import login_response
from jwt_multiauth.models import OtpChallenge
from jwt_multiauth.serializers import (
    LoginPendingTwoFactorResponseSerializer,
    LoginTokensResponseSerializer,
    OtpRequestResponseSerializer,
    OtpRequestSerializer,
    OtpResendSerializer,
    OtpVerifySerializer,
)
from jwt_multiauth.services import ChallengeInvalid, OtpService, RequestMeta

_VERIFY_RESPONSE = PolymorphicProxySerializer(
    component_name="OtpVerifyResponse",
    serializers=[LoginTokensResponseSerializer, LoginPendingTwoFactorResponseSerializer],
    resource_type_field_name=None,
)


class OtpRequestView(generics.GenericAPIView[Any]):
    """``POST /otp/request/``. Rejects (``400``) a ``channel`` whose auth method isn't in
    ``ALLOWED_AUTH_METHODS`` for login — checked BEFORE ``OtpService.request`` is ever called, so
    a host that only enabled ``email_otp`` never accepts a ``phone_otp`` request even for a real
    phone-having user.
    """

    serializer_class = OtpRequestSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = []  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.OTP_REQUEST

    @extend_schema(
        summary="Request a login OTP challenge",
        description=(
            "Real or decoy, indistinguishably — this endpoint never reveals whether `identifier` "
            "resolves to a real account. 400 only when `channel`'s auth method isn't enabled."
        ),
        request=OtpRequestSerializer,
        responses={
            200: OtpRequestResponseSerializer,
            400: OpenApiResponse(
                description="channel's auth method is not in ALLOWED_AUTH_METHODS."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["identifier"]
        channel = serializer.validated_data["channel"]

        method = otp.method_for_channel(channel)
        if method not in conf.get_setting("ALLOWED_AUTH_METHODS"):
            raise ValidationError({"code": "channel_not_allowed"})

        result = OtpService.request(identifier, channel=channel, purpose="login")
        return Response(
            {
                "challenge_id": result.challenge_id,
                "expires_at": result.expires_at,
                "resend_available_at": result.resend_available_at,
            }
        )


class OtpVerifyView(generics.GenericAPIView[Any]):
    """``POST /otp/verify/``. Accepts EITHER ``code`` OR ``link_token`` — this is where the
    magic-link variant lives. A challenge that doesn't resolve, is expired/consumed/exhausted, or
    isn't ``purpose="login"`` (guarding against redeeming a ``password_reset``/``verify_contact``
    challenge for a session) all collapse into the identical ``otp_challenge_invalid`` shape.
    Success runs through the SAME shared login-response helper as ``/login/``.

    ``authentication_classes`` carries ``JWTAuthentication`` for the same reason ``LoginView``
    does — without a registered authenticator, DRF downgrades every ``AuthenticationFailed``
    raised by ``login_response`` (the ``two_factor_unavailable`` case) from ``401`` to ``403``.
    """

    serializer_class = OtpVerifySerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.OTP_VERIFY

    @extend_schema(
        summary="Verify an OTP code or magic-link token and complete login",
        description=(
            "Exactly one of `code`/`link_token` is required. Returns the same shape as "
            "`/login/`. `created` is `true` only when this call just auto-provisioned a new "
            "account for an unrecognized identifier on an AUTO_PROVISION_METHODS-enabled method."
        ),
        request=OtpVerifySerializer,
        responses={
            200: _VERIFY_RESPONSE,
            400: OpenApiResponse(
                description="Invalid, expired, consumed, or wrong-purpose challenge."
            ),
            401: OpenApiResponse(description="2FA required with no eligible second factor."),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            result = OtpService.verify(
                data["challenge_id"], code=data.get("code"), link_token=data.get("link_token")
            )
        except ChallengeInvalid as exc:
            raise ValidationError({"code": "otp_challenge_invalid"}) from exc

        if result.purpose != "login":
            # Same shape as any other ChallengeInvalid — a password_reset/verify_contact
            # challenge redeemed here must be indistinguishable from an expired/decoy one.
            raise ValidationError({"code": "otp_challenge_invalid"})

        challenge = OtpChallenge.objects.get(pk=data["challenge_id"])
        primary_method = otp.method_for_channel(challenge.channel)
        request_meta: RequestMeta = {
            "ip": client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "device_label": "",
            "method": primary_method,
        }
        return login_response(
            result.user,
            request=request,
            request_meta=request_meta,
            remember_me=False,
            created=result.created,
            used_primary_channel=challenge.channel,
            primary_method=primary_method,
        )


class OtpResendView(generics.GenericAPIView[Any]):
    """``POST /otp/resend/``. Same ``otp_challenge_invalid`` shape whether the challenge is real,
    decoy, or cooldown-blocked.
    """

    serializer_class = OtpResendSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = []  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.OTP_RESEND

    @extend_schema(
        summary="Resend an OTP challenge's code",
        description="Reuses the same challenge_id/destination with a fresh code and expiry.",
        request=OtpResendSerializer,
        responses={
            200: OtpRequestResponseSerializer,
            400: OpenApiResponse(
                description="Invalid challenge, cooldown not elapsed, or MAX_RESENDS exhausted."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = OtpService.resend(serializer.validated_data["challenge_id"])
        except ChallengeInvalid as exc:
            raise ValidationError({"code": "otp_challenge_invalid"}) from exc
        return Response(
            {
                "challenge_id": result.challenge_id,
                "expires_at": result.expires_at,
                "resend_available_at": result.resend_available_at,
            }
        )

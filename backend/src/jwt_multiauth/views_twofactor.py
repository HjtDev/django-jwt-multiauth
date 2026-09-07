"""Two-factor authentication self-service views: verify, status, TOTP enroll/confirm, disable,
recovery-code regenerate.

Phase 7 implements the views backing ``urls.py``'s ``/2fa/verify/``, ``/2fa/status/``,
``/2fa/totp/enroll/``, ``/2fa/totp/confirm/``, ``/2fa/disable/``,
``/2fa/recovery-codes/regenerate/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md``
§5. ``TWO_FACTOR["REQUIRE_DIFFERENT_CHANNEL"]`` leaving a user with zero eligible methods fails
the login outright — never degrades to single-factor (this repo's CLAUDE.md rule 3). No endpoint
here (or anywhere in this app) returns an access token before a required second factor completes,
under any settings combination. ``TwoFactorService`` (``services.py``, Phase 5/7) does the actual
enrollment/verification work; this module only translates HTTP <-> service calls.

Also implements ``POST /2fa/otp/request/`` — NOT in ``docs/CONTRACT.md``'s frozen §5 table, a
Phase 7 addition recorded as a deviation in its §11 register: ``email_otp``/``phone_otp`` as a
SECOND factor needs an OTP challenge of their own (``purpose="two_factor"``), but
``/otp/request/`` (Phase 6) is hardcoded to ``purpose="login"`` and takes no pending token, and
``/2fa/verify/``'s frozen request body carries no ``challenge_id`` for one to be requested
against. This endpoint mirrors ``/otp/request/``'s shape, gated by the pending token itself
rather than an identifier.
"""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from jwt_multiauth import conf, throttling
from jwt_multiauth.authentication import JWTAuthentication
from jwt_multiauth.login_flow import pair_response
from jwt_multiauth.models import RecoveryCode, TwoFactorDevice, VerifiedContact
from jwt_multiauth.serializers import (
    RecoveryCodesRegenerateSerializer,
    RecoveryCodesResponseSerializer,
    TotpConfirmSerializer,
    TotpEnrollResponseSerializer,
    TwoFactorDisableSerializer,
    TwoFactorOtpRequestSerializer,
    TwoFactorStatusResponseSerializer,
    TwoFactorVerifySerializer,
)
from jwt_multiauth.services import (
    ChallengeInvalid,
    InvalidPendingToken,
    OtpService,
    TwoFactorService,
    TwoFactorUnavailable,
)


def _require_password_reauth(user: Any, password: str) -> None:
    """Shared re-auth step for ``/2fa/disable/`` and ``/2fa/recovery-codes/regenerate/``
    (``docs/CONTRACT.md`` §5: password re-entry, decided once — "since it's available regardless
    of which method is being disabled" — and applied consistently to both routes). A single
    function so "reachable without re-auth" is one thing to audit, not two separate view bodies.
    """
    if not user.check_password(password):
        raise ValidationError({"password": ["Incorrect password."]})


class TwoFactorStatusView(generics.GenericAPIView[Any]):
    """``GET /2fa/status/``. ``enrolled_methods`` reflects what the user has actually set up,
    independent of ``TWO_FACTOR["ALLOWED_METHODS"]`` (a device enrolled before a host narrowed
    its allowlist still shows here); ``eligible_methods`` is the ``ALLOWED_METHODS``-filtered
    view — what ``TwoFactorService.eligible_methods`` would return. Computed with
    ``used_primary_channel="password"`` — the channel the different-channel rule never strips
    anything for (docs/CONTRACT.md §4) — since this is a standalone status check with no actual
    login/primary-channel context to compare against; the real enforcement of the different-
    channel rule happens inside ``verify_second_factor``'s own re-derivation, never here.
    """

    serializer_class = TwoFactorStatusResponseSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_STATUS

    @extend_schema(
        summary="Get the caller's own 2FA enrollment and eligibility status",
        description=(
            "`enrolled_methods` is what the caller has actually set up; `eligible_methods` is "
            'that set filtered by the host\'s current TWO_FACTOR["ALLOWED_METHODS"].'
        ),
        responses={200: TwoFactorStatusResponseSerializer},
        tags=["jwt-multiauth"],
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        # Typed Any, matching every services.py signature's own `user: Any` — request.user's
        # `User | AnonymousUser` type is stricter than a raw FK filter's stub expects, the same
        # mismatch every service method sidesteps by never typing `user` as the concrete model.
        user: Any = request.user
        user_fields = conf.get_setting("USER_FIELDS")

        enrolled: list[str] = []
        if TwoFactorDevice.objects.filter(
            user=user, method="totp", confirmed_at__isnull=False, disabled_at__isnull=True
        ).exists():
            enrolled.append("totp")
        for method, field in (("email_otp", "email"), ("phone_otp", "phone")):
            field_name = user_fields["EMAIL_FIELD" if field == "email" else "PHONE_FIELD"]
            value = getattr(user, field_name, "") if field_name else ""
            if (
                value
                and VerifiedContact.objects.filter(user=user, field=field, value=value).exists()
            ):
                enrolled.append(method)
        if RecoveryCode.objects.filter(user=user, used_at__isnull=True).exists():
            enrolled.append("recovery_code")

        eligible = TwoFactorService.eligible_methods(user, used_primary_channel="password")
        return Response(
            {
                "policy": conf.get_setting("TWO_FACTOR")["POLICY"],
                "enrolled_methods": enrolled,
                "eligible_methods": eligible,
            }
        )


class TotpEnrollView(generics.GenericAPIView[Any]):
    """``POST /2fa/totp/enroll/``. The ONE moment the plaintext TOTP secret is ever returned —
    never retrievable again afterward, not even by this same endpoint (a repeat call replaces the
    pending enrollment and returns a NEW secret, never the previous one).
    """

    serializer_class = TotpEnrollResponseSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_TOTP_ENROLL

    @extend_schema(
        summary="Start a TOTP enrollment",
        description=(
            "Returns a plaintext secret and an otpauth:// URI, once. A prior unconfirmed (or "
            "disabled) enrollment is silently replaced. Confirm with POST /2fa/totp/confirm/ "
            "before this method counts toward eligible_methods."
        ),
        responses={200: TotpEnrollResponseSerializer},
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        enrollment = TwoFactorService.enroll_totp(request.user)
        return Response({"secret": enrollment.secret, "otpauth_uri": enrollment.otpauth_uri})


class TotpConfirmView(generics.GenericAPIView[Any]):
    """``POST /2fa/totp/confirm/``. Rejects a confirm attempt against an already-confirmed
    device, or with no pending enrollment at all, with the same ``400`` shape as a wrong code —
    every rejection here is a validation failure, never a distinguishable error.
    """

    serializer_class = TotpConfirmSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_TOTP_CONFIRM

    @extend_schema(
        summary="Confirm a pending TOTP enrollment",
        request=TotpConfirmSerializer,
        responses={
            204: None,
            400: OpenApiResponse(
                description="No pending enrollment, already confirmed, or an invalid code."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            TwoFactorService.confirm_totp(request.user, code=serializer.validated_data["code"])
        except DjangoValidationError as exc:
            raise ValidationError(
                {"code": getattr(exc, "code", None) or "invalid_totp_code"}
            ) from exc
        return Response(status=204)


class TwoFactorDisableView(generics.GenericAPIView[Any]):
    """``POST /2fa/disable/``. Requires the caller's current password, regardless of which
    method is being disabled (docs/CONTRACT.md §5's own reasoning — password is available no
    matter which factor is being turned off).
    """

    serializer_class = TwoFactorDisableSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_DISABLE

    @extend_schema(
        summary="Disable one enrolled 2FA method",
        description="Requires the caller's current password as a re-auth step.",
        request=TwoFactorDisableSerializer,
        responses={
            204: None,
            400: OpenApiResponse(
                description="method is not currently enrolled, or an incorrect password."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_password_reauth(request.user, serializer.validated_data["password"])
        try:
            TwoFactorService.disable(request.user, method=serializer.validated_data["method"])
        except DjangoValidationError as exc:
            raise ValidationError(
                {"code": getattr(exc, "code", None) or "method_not_enrolled"}
            ) from exc
        return Response(status=204)


class RecoveryCodesRegenerateView(generics.GenericAPIView[Any]):
    """``POST /2fa/recovery-codes/regenerate/``. Invalidates every prior unused code before
    generating a fresh batch — a regenerated set never coexists with a stale one.
    """

    serializer_class = RecoveryCodesRegenerateSerializer
    permission_classes = [IsAuthenticated]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_RECOVERY_REGENERATE

    @extend_schema(
        summary="Regenerate the caller's recovery codes",
        description=(
            "Requires the caller's current password as a re-auth step. Returns the PLAINTEXT "
            "codes once — never retrievable again."
        ),
        request=RecoveryCodesRegenerateSerializer,
        responses={
            200: RecoveryCodesResponseSerializer,
            400: OpenApiResponse(description="Incorrect password."),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_password_reauth(request.user, serializer.validated_data["password"])
        codes = TwoFactorService.generate_recovery_codes(request.user)
        return Response({"codes": codes})


class TwoFactorOtpRequestView(generics.GenericAPIView[Any]):
    """``POST /2fa/otp/request/`` — not in ``docs/CONTRACT.md``'s frozen §5 table (see this
    module's own docstring). Gated by the pending token itself rather than an identifier: no
    decoy path applies, since the caller already proved a primary factor to obtain the pending
    token in the first place — unlike ``/otp/request/``, there is no unauthenticated-identifier
    enumeration surface here to protect.
    """

    serializer_class = TwoFactorOtpRequestSerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_OTP_REQUEST

    @extend_schema(
        summary="Request a two_factor-purpose OTP challenge for an eligible email_otp/phone_otp "
        "second factor",
        request=TwoFactorOtpRequestSerializer,
        responses={
            200: OpenApiResponse(description="challenge_id, expires_at, resend_available_at."),
            401: OpenApiResponse(
                description="Invalid/expired pending token, or method not eligible."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            user, _claims, eligible = TwoFactorService.resolve_pending(data["pending_token"])
        except InvalidPendingToken as exc:
            raise AuthenticationFailed({"code": "invalid_pending_token"}) from exc

        method = data["method"]
        if method not in eligible:
            raise AuthenticationFailed({"code": "two_factor_unavailable"})

        field = "email" if method == "email_otp" else "phone"
        user_fields = conf.get_setting("USER_FIELDS")
        field_name = user_fields["EMAIL_FIELD" if field == "email" else "PHONE_FIELD"]
        # `method in eligible` already proves a VerifiedContact matches the user's current value
        # for this field (TwoFactorService.eligible_methods' own resolution rule) — value is
        # never empty here.
        value = getattr(user, field_name, "") if field_name else ""
        result = OtpService.request(value, channel=field, purpose="two_factor")
        return Response(
            {
                "challenge_id": result.challenge_id,
                "expires_at": result.expires_at,
                "resend_available_at": result.resend_available_at,
            }
        )


class TwoFactorVerifyView(generics.GenericAPIView[Any]):
    """``POST /2fa/verify/``. Unauthenticated except for the pending token itself — intentionally
    reachable pre-full-login, since redeeming that token for real tokens is the whole point.
    Every failure here — a wrong code, an ineligible method, an already-consumed or invalid
    pending token — is a ``401``, never a ``400``: ``docs/CONTRACT.md`` §5's own row for this
    endpoint lists only ``200``/``401`` as possible responses, so ``ChallengeInvalid`` (widened
    in Phase 7 to also cover a wrong TOTP/recovery code, not just an ``OtpChallenge`` mismatch —
    see ``TwoFactorService.verify_second_factor``'s own docstring) maps to ``401`` here, unlike
    ``OtpVerifyView``'s ``400`` mapping for the same exception.

    ``authentication_classes`` carries ``JWTAuthentication`` for the same reason ``LoginView``
    does — without a registered authenticator, DRF downgrades every ``AuthenticationFailed``
    raised below from ``401`` to ``403``.
    """

    serializer_class = TwoFactorVerifySerializer
    permission_classes = [AllowAny]  # noqa: RUF012 -- APIView types this as an instance var
    authentication_classes = [JWTAuthentication]  # noqa: RUF012
    throttle_classes = [ScopedRateThrottle]  # noqa: RUF012
    throttle_scope = throttling.TWO_FACTOR_VERIFY

    @extend_schema(
        summary="Redeem a pending 2FA token with a second-factor code",
        description=(
            "Exactly one of `code`/`link_token` is required. `challenge_id` is required for "
            "email_otp/phone_otp (obtained from POST /2fa/otp/request/). The server re-derives "
            "eligible methods itself — a client-claimed `method` not in that fresh set is "
            "rejected even if the client presents an otherwise-valid code for it."
        ),
        request=TwoFactorVerifySerializer,
        responses={
            200: OpenApiResponse(description="{access, session_id, created}."),
            401: OpenApiResponse(
                description="Invalid/consumed pending token, or method not eligible/verified."
            ),
        },
        tags=["jwt-multiauth"],
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            pair = TwoFactorService.verify_second_factor(
                data["pending_token"],
                method=data["method"],
                code=data.get("code"),
                link_token=data.get("link_token"),
                challenge_id=data.get("challenge_id"),
                trust_device=data["trust_device"],
            )
        except InvalidPendingToken as exc:
            raise AuthenticationFailed({"code": "invalid_pending_token"}) from exc
        except TwoFactorUnavailable as exc:
            raise AuthenticationFailed({"code": "two_factor_unavailable"}) from exc
        except ChallengeInvalid as exc:
            raise AuthenticationFailed({"code": "otp_challenge_invalid"}) from exc

        return pair_response(pair, remember_me=False, created=False)

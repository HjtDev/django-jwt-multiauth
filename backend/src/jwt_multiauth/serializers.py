"""Request/response serializers for every self-service and admin view.

Populated alongside each ``views_*``/``admin_views.py`` module as it lands (Phases 6-8), per
``docs/CONTRACT.md`` §5. Explicit field lists throughout — no serializer here ever uses
``fields = "__all__"``, and no response ever exposes a password, a code, a ``code_hash``, a
``token_hash``, or ``secret_encrypted`` (this repo's ``CLAUDE.md`` rule listed under §5).

Phase 6 adds the login/OTP/discovery request and response shapes. A response serializer here
represents a SUCCESS body only — a failure never goes through one of these, it goes through
``appkit.exceptions.standard_exception_handler``'s envelope instead (``docs/CONTRACT.md`` §10).
"""

from __future__ import annotations

from typing import Any

from rest_framework import serializers


class LoginRequestSerializer(serializers.Serializer[Any]):
    identifier = serializers.CharField()
    password = serializers.CharField(trim_whitespace=False, write_only=True)
    remember_me = serializers.BooleanField(default=False)


class LoginTokensResponseSerializer(serializers.Serializer[Any]):
    """The no-2FA-required branch of the shared login response (``docs/CONTRACT.md`` §5's
    ``/login/``/``/otp/verify/`` rows). ``refresh`` is present only when
    ``REFRESH_COOKIE["TRANSPORT"] == "body"`` — omitted (never null) under the default
    ``"cookie"`` transport, where the refresh token travels as an HttpOnly cookie instead.
    """

    access = serializers.CharField()
    refresh = serializers.CharField(required=False)
    session_id = serializers.CharField()
    created = serializers.BooleanField()


class LoginPendingTwoFactorResponseSerializer(serializers.Serializer[Any]):
    """The 2FA-required branch of the shared login response. HTTP 200 — this is not an error
    response and is never wrapped in appkit's error envelope (``docs/CONTRACT.md`` §5).
    """

    pending_token = serializers.CharField()
    eligible_methods = serializers.ListField(child=serializers.CharField())


class PasswordChangeSerializer(serializers.Serializer[Any]):
    old_password = serializers.CharField(trim_whitespace=False, write_only=True)
    new_password = serializers.CharField(trim_whitespace=False, write_only=True)


class PasswordResetRequestSerializer(serializers.Serializer[Any]):
    identifier = serializers.CharField()


class PasswordResetConfirmSerializer(serializers.Serializer[Any]):
    challenge_id = serializers.CharField()
    code = serializers.CharField(required=False, allow_blank=False, write_only=True)
    link_token = serializers.CharField(required=False, allow_blank=False, write_only=True)
    new_password = serializers.CharField(trim_whitespace=False, write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        return _validate_exactly_one_of_code_or_link_token(attrs)


class OtpRequestSerializer(serializers.Serializer[Any]):
    identifier = serializers.CharField()
    channel = serializers.ChoiceField(choices=["email", "phone"])


class OtpRequestResponseSerializer(serializers.Serializer[Any]):
    challenge_id = serializers.CharField()
    expires_at = serializers.DateTimeField()
    resend_available_at = serializers.DateTimeField()


class OtpVerifySerializer(serializers.Serializer[Any]):
    challenge_id = serializers.CharField()
    code = serializers.CharField(required=False, allow_blank=False, write_only=True)
    link_token = serializers.CharField(required=False, allow_blank=False, write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        return _validate_exactly_one_of_code_or_link_token(attrs)


class OtpResendSerializer(serializers.Serializer[Any]):
    challenge_id = serializers.CharField()


class TwoFactorMethodsSerializer(serializers.Serializer[Any]):
    policy = serializers.CharField()
    allowed_methods = serializers.ListField(child=serializers.CharField())


class AuthMethodsResponseSerializer(serializers.Serializer[Any]):
    allowed_auth_methods = serializers.ListField(child=serializers.CharField())
    two_factor = TwoFactorMethodsSerializer()


#: The closed set of 2FA method strings — mirrors TWO_FACTOR["ALLOWED_METHODS"]'s own closed set
#: (checks.py's E006), used wherever a request body names a specific method rather than merely
#: listing eligible ones.
_TWO_FACTOR_METHOD_CHOICES = ["totp", "email_otp", "phone_otp", "recovery_code"]


class TwoFactorStatusResponseSerializer(serializers.Serializer[Any]):
    """``GET /2fa/status/`` response — ``docs/CONTRACT.md`` §5."""

    policy = serializers.CharField()
    enrolled_methods = serializers.ListField(child=serializers.CharField())
    eligible_methods = serializers.ListField(child=serializers.CharField())


class TotpEnrollResponseSerializer(serializers.Serializer[Any]):
    """``POST /2fa/totp/enroll/`` response. The ONE moment the plaintext secret is ever
    returned — never present in any other response this app produces.
    """

    secret = serializers.CharField()
    otpauth_uri = serializers.CharField()


class TotpConfirmSerializer(serializers.Serializer[Any]):
    code = serializers.CharField(write_only=True)


class TwoFactorDisableSerializer(serializers.Serializer[Any]):
    method = serializers.ChoiceField(choices=_TWO_FACTOR_METHOD_CHOICES)
    password = serializers.CharField(trim_whitespace=False, write_only=True)


class RecoveryCodesRegenerateSerializer(serializers.Serializer[Any]):
    password = serializers.CharField(trim_whitespace=False, write_only=True)


class RecoveryCodesResponseSerializer(serializers.Serializer[Any]):
    """The PLAINTEXT recovery codes — returned once, the same rule as the TOTP secret."""

    codes = serializers.ListField(child=serializers.CharField())


class TwoFactorOtpRequestSerializer(serializers.Serializer[Any]):
    """``POST /2fa/otp/request/`` — not in ``docs/CONTRACT.md``'s frozen §5 table, a Phase 7
    addition recorded as a deviation in its §11 register: ``/2fa/verify/``'s frozen body has no
    ``challenge_id`` of its own, and ``/otp/request/`` is hardcoded to ``purpose="login"``, so
    ``email_otp``/``phone_otp`` as a SECOND factor needs its own request step, gated by the
    pending token itself rather than an identifier (this endpoint never takes one).
    """

    pending_token = serializers.CharField()
    method = serializers.ChoiceField(choices=["email_otp", "phone_otp"])


class TwoFactorVerifySerializer(serializers.Serializer[Any]):
    """``POST /2fa/verify/`` — ``docs/CONTRACT.md`` §5. Every method here needs exactly one of
    ``code``/``link_token`` (``totp``/``recovery_code`` always via ``code``; ``email_otp``/
    ``phone_otp`` via either, same magic-link-lives-here rule ``OtpVerifySerializer`` uses), so
    the shared cross-field helper applies universally, not just to the OTP-based methods.
    ``challenge_id`` is an addition beyond the frozen body (same §11 deviation as
    ``TwoFactorOtpRequestSerializer`` above) — required only for ``"email_otp"``/``"phone_otp"``,
    a method-conditional rule checked at the view layer rather than here.
    """

    pending_token = serializers.CharField()
    method = serializers.ChoiceField(choices=_TWO_FACTOR_METHOD_CHOICES)
    code = serializers.CharField(required=False, allow_blank=False, write_only=True)
    link_token = serializers.CharField(required=False, allow_blank=False, write_only=True)
    challenge_id = serializers.CharField(required=False, allow_blank=False)
    trust_device = serializers.BooleanField(default=False)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        return _validate_exactly_one_of_code_or_link_token(attrs)


def _validate_exactly_one_of_code_or_link_token(attrs: dict[str, Any]) -> dict[str, Any]:
    """Shared cross-field rule for every serializer accepting ``code? or link_token?``
    (``docs/CONTRACT.md`` §5: "exactly one required, magic-link lives here, not a separate
    view") — both present or both absent are equally invalid, so this collapses to one
    ``ValidationError`` rather than two near-duplicate ``validate()`` bodies.
    """
    has_code = bool(attrs.get("code"))
    has_link_token = bool(attrs.get("link_token"))
    if has_code == has_link_token:
        raise serializers.ValidationError(
            "Exactly one of 'code' or 'link_token' is required.", code="exactly_one_required"
        )
    return attrs

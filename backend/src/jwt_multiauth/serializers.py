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

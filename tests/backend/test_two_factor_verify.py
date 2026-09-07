"""Proves ``services.TwoFactorService.verify_second_factor`` — the actual enforcement point for
the different-channel rule (``eligible_methods`` itself is advisory; this method RE-DERIVES it
server-side and rejects a client-supplied ``method`` not in that fresh set, docs/CONTRACT.md §4/
§10). Full round trip per method, the different-channel rejection, the lying-client rejection,
TOTP/recovery-code replay guards, and pending-token single-use.

Every ``verify_second_factor`` call here builds its own ``pending_token`` directly via
``TokenService.issue_pending_2fa_token`` — this file proves the SERVICE layer; the HTTP layer
(``/2fa/verify/`` itself) is proven separately in ``test_views_twofactor.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.test import override_settings
from freezegun import freeze_time

from jwt_multiauth.factories import UserFactory, VerifiedContactFactory
from jwt_multiauth.models import RecoveryCode, TrustedDevice
from jwt_multiauth.services import (
    ChallengeInvalid,
    InvalidPendingToken,
    OtpService,
    RequestMeta,
    TokenService,
    TwoFactorService,
    TwoFactorTokenPair,
    TwoFactorUnavailable,
)
from jwt_multiauth.signals import email_otp_requested, otp_verified
from tests.backend.conftest import captured

#: A hard `import pyotp` at module scope would crash collection under the bare-install leg
#: (`make test-bare`) BEFORE `pytestmark`'s `requires_extra` marker ever gets a chance to
#: deselect anything — marker filtering only applies to already-collected tests.
#: `importorskip` converts that would-be collection error into a clean whole-module skip instead.
pyotp = pytest.importorskip("pyotp")

pytestmark = [pytest.mark.django_db, pytest.mark.requires_extra]

_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}

#: A fixed base time — every TOTP-touching test below freezes time explicitly, one TOTP step
#: (pyotp's default interval, 30s) apart per code generated, so a confirm code and a subsequent
#: login code are never accidentally the same step: TwoFactorDevice.last_used_step is seeded by
#: confirm_totp itself (docs/CONTRACT.md §4's own replay-guard requirement), so reusing the SAME
#: 30s window for both would make the "round trip" tests indistinguishable from the replay-guard
#: tests they sit next to.
_BASE_TIME = datetime(2026, 1, 1, 0, 0, 0)
_STEP = timedelta(seconds=30)


def _pending_token(user: object, *, primary_method: str = "password") -> str:
    return TokenService.issue_pending_2fa_token(
        user, primary_method=primary_method, request_meta=_REQUEST_META
    )


def _enroll_and_confirm_totp(user: object) -> str:
    """Enrolls and confirms a TOTP device at ``_BASE_TIME``, returning the plaintext secret.
    Callers generate/verify subsequent login codes at a LATER frozen step (see ``_STEP``) so the
    replay guard ``confirm_totp`` itself seeds never rejects the very next legitimate login.
    """
    enrollment = TwoFactorService.enroll_totp(user)
    with freeze_time(_BASE_TIME):
        TwoFactorService.confirm_totp(user, code=pyotp.TOTP(enrollment.secret).now())
    return enrollment.secret


def _request_two_factor_email_otp(destination: str) -> tuple[str, str]:
    """Requests a real purpose="two_factor" OTP challenge directly via ``OtpService.request`` —
    bypassing the eligibility gate a real client hits at ``POST /2fa/otp/request/`` (Phase 7's own
    addition, ``views_twofactor.py``) — and returns ``(code, challenge_id)``. Used to simulate a
    client that already holds a REAL, valid code for a method the server ultimately rejects.
    """
    with captured(email_otp_requested) as received:
        OtpService.request(destination, channel="email", purpose="two_factor")
    return received[0]["code"], received[0]["challenge_id"]


# --------------------------------------------------------------------------- full round trips


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_totp_round_trip() -> None:
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = _pending_token(user)
        pair = TwoFactorService.verify_second_factor(
            pending_token, method="totp", code=pyotp.TOTP(secret).now()
        )
    assert pair.access
    assert pair.refresh
    assert pair.session_id


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["email_otp"]},
    }
)
def test_email_otp_round_trip() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    code, challenge_id = _request_two_factor_email_otp("alice@example.com")

    with captured(otp_verified) as verified:
        pending_token = _pending_token(user, primary_method="password")
        pair = TwoFactorService.verify_second_factor(
            pending_token, method="email_otp", code=code, challenge_id=challenge_id
        )

    assert pair.access
    # otp_verified fires from inside OtpService.verify itself for an OTP-based second factor.
    assert len(verified) == 1
    assert verified[0]["purpose"] == "two_factor"


@override_settings(
    JWT_MULTIAUTH={
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp", "recovery_code"]}
    }
)
def test_recovery_code_round_trip() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=pyotp.TOTP(enrollment.secret).now())
    codes = TwoFactorService.generate_recovery_codes(user)

    pending_token = _pending_token(user)
    pair = TwoFactorService.verify_second_factor(
        pending_token, method="recovery_code", code=codes[0]
    )
    assert pair.access
    assert RecoveryCode.objects.filter(user=user, used_at__isnull=False).exists()


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_totp_verification_does_not_fire_otp_verified() -> None:
    """otp_verified is sent by OtpService.verify() only — totp has no OtpChallenge involved."""
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with captured(otp_verified) as verified, freeze_time(_BASE_TIME + _STEP):
        pending_token = _pending_token(user)
        TwoFactorService.verify_second_factor(
            pending_token, method="totp", code=pyotp.TOTP(secret).now()
        )
    assert verified == []


# --------------------------------------------------------------------- different-channel rule


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {
            "POLICY": "required",
            "ALLOWED_METHODS": ["email_otp"],
            "REQUIRE_DIFFERENT_CHANNEL": True,
        },
    }
)
def test_different_channel_rejection_same_method_as_primary() -> None:
    """A user who logged in via email_otp, whose ONLY enrolled 2FA method is ALSO email_otp,
    gets two_factor_unavailable rather than being offered email_otp again — even with a real,
    valid two_factor OTP code in hand.
    """
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    code, challenge_id = _request_two_factor_email_otp("alice@example.com")

    pending_token = _pending_token(user, primary_method="email_otp")
    with pytest.raises(TwoFactorUnavailable):
        TwoFactorService.verify_second_factor(
            pending_token, method="email_otp", code=code, challenge_id=challenge_id
        )


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]},
    }
)
def test_lying_client_is_rejected_even_with_an_otherwise_valid_code() -> None:
    """The mutation-test target: the server's own re-derived eligible_methods is ["totp"] only
    (email_otp isn't even in ALLOWED_METHODS here) — a client claiming method="email_otp" with a
    REAL, valid two_factor OTP code (obtained directly via OtpService.request, bypassing the
    eligibility gate a real client would hit at POST /2fa/otp/request/) must still be rejected.
    Removing verify_second_factor's `if method not in eligible: raise TwoFactorUnavailable` check
    makes this test fail — it would otherwise happily verify the code and issue real tokens.
    """
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=pyotp.TOTP(enrollment.secret).now())
    code, challenge_id = _request_two_factor_email_otp("alice@example.com")

    pending_token = _pending_token(user, primary_method="password")
    with pytest.raises(TwoFactorUnavailable):
        TwoFactorService.verify_second_factor(
            pending_token, method="email_otp", code=code, challenge_id=challenge_id
        )


@override_settings(
    JWT_MULTIAUTH={
        "TWO_FACTOR": {
            "POLICY": "required",
            "ALLOWED_METHODS": ["email_otp", "recovery_code"],
            "REQUIRE_DIFFERENT_CHANNEL": True,
        },
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
    }
)
def test_recovery_code_alone_is_rejected_when_different_channel_strips_the_only_real_method() -> (
    None
):
    """Mirrors test_two_factor_eligibility.py's own invariant, asserted here at the verify layer:
    recovery_code is never a usable second factor on its own, so a client presenting a real
    recovery code is still rejected when the different-channel filter would otherwise leave
    ["recovery_code"] as the only entry.
    """
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    codes = TwoFactorService.generate_recovery_codes(user)

    pending_token = _pending_token(user, primary_method="email_otp")
    with pytest.raises(TwoFactorUnavailable):
        TwoFactorService.verify_second_factor(pending_token, method="recovery_code", code=codes[0])


# ------------------------------------------------------------------------------- replay guards


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_totp_replay_is_rejected() -> None:
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with freeze_time(_BASE_TIME + _STEP):
        code = pyotp.TOTP(secret).now()
        first_token = _pending_token(user)
        TwoFactorService.verify_second_factor(first_token, method="totp", code=code)

        second_token = _pending_token(user)
        with pytest.raises(ChallengeInvalid):
            TwoFactorService.verify_second_factor(second_token, method="totp", code=code)


@override_settings(
    JWT_MULTIAUTH={
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp", "recovery_code"]}
    }
)
def test_recovery_code_is_single_use() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=pyotp.TOTP(enrollment.secret).now())
    codes = TwoFactorService.generate_recovery_codes(user)

    first_token = _pending_token(user)
    TwoFactorService.verify_second_factor(first_token, method="recovery_code", code=codes[0])

    second_token = _pending_token(user)
    with pytest.raises(ChallengeInvalid):
        TwoFactorService.verify_second_factor(second_token, method="recovery_code", code=codes[0])


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_pending_token_cannot_be_replayed_after_a_successful_verify() -> None:
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = _pending_token(user)
        TwoFactorService.verify_second_factor(
            pending_token, method="totp", code=pyotp.TOTP(secret).now()
        )

        # The consumed-jti check runs BEFORE per-method verification, so the second call fails
        # on the pending token alone regardless of the code presented.
        with pytest.raises(InvalidPendingToken):
            TwoFactorService.verify_second_factor(
                pending_token, method="totp", code=pyotp.TOTP(secret).now()
            )


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_wrong_code_does_not_consume_the_pending_token() -> None:
    """A user who mistypes their code must be able to retry with the pending token they already
    have — only a SUCCESSFUL verify consumes it.
    """
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = _pending_token(user)
        with pytest.raises(ChallengeInvalid):
            TwoFactorService.verify_second_factor(pending_token, method="totp", code="000000")

        pair = TwoFactorService.verify_second_factor(
            pending_token, method="totp", code=pyotp.TOTP(secret).now()
        )
    assert pair.access


# ----------------------------------------------------------------------------------- other cases


def test_invalid_pending_token_is_rejected() -> None:
    with pytest.raises(InvalidPendingToken):
        TwoFactorService.verify_second_factor("not-a-real-token", method="totp", code="000000")


@override_settings(
    JWT_MULTIAUTH={
        "TWO_FACTOR": {
            "POLICY": "required",
            "ALLOWED_METHODS": ["totp"],
            "TRUSTED_DEVICE": {"ENABLED": True},
        }
    }
)
def test_trust_device_issues_a_trusted_device_token_when_enabled() -> None:
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = _pending_token(user)
        pair = TwoFactorService.verify_second_factor(
            pending_token,
            method="totp",
            code=pyotp.TOTP(secret).now(),
            trust_device=True,
        )
    assert isinstance(pair, TwoFactorTokenPair)
    assert pair.trusted_device_token
    assert TrustedDevice.objects.filter(user=user, revoked_at__isnull=True).exists()


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp"]}}
)
def test_trust_device_does_not_issue_a_token_when_trusted_device_is_disabled() -> None:
    """TRUSTED_DEVICE["ENABLED"] defaults to False — trust_device=True alone is not enough."""
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)

    with freeze_time(_BASE_TIME + _STEP):
        pending_token = _pending_token(user)
        pair = TwoFactorService.verify_second_factor(
            pending_token,
            method="totp",
            code=pyotp.TOTP(secret).now(),
            trust_device=True,
        )
    assert getattr(pair, "trusted_device_token", None) is None


# --------------------------------------------------------------------- per-method edge cases


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["email_otp"]},
    }
)
def test_email_otp_without_a_challenge_id_is_rejected() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")

    pending_token = _pending_token(user, primary_method="password")
    with pytest.raises(ChallengeInvalid):
        TwoFactorService.verify_second_factor(pending_token, method="email_otp", code="123456")


@override_settings(
    JWT_MULTIAUTH={
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["email_otp"]},
    }
)
def test_email_otp_rejects_a_challenge_of_the_wrong_purpose() -> None:
    """A login-purpose challenge redeemed at /2fa/verify/ must not be accepted as a second
    factor — only a purpose="two_factor" challenge counts.
    """
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")

    with captured(email_otp_requested) as received:
        OtpService.request("alice@example.com", channel="email", purpose="login")
    code, challenge_id = received[0]["code"], received[0]["challenge_id"]

    pending_token = _pending_token(user, primary_method="password")
    with pytest.raises(ChallengeInvalid):
        TwoFactorService.verify_second_factor(
            pending_token, method="email_otp", code=code, challenge_id=challenge_id
        )


@override_settings(
    JWT_MULTIAUTH={
        "TWO_FACTOR": {"POLICY": "required", "ALLOWED_METHODS": ["totp", "recovery_code"]}
    }
)
def test_recovery_code_without_a_code_is_rejected() -> None:
    user = UserFactory()
    secret = _enroll_and_confirm_totp(user)
    TwoFactorService.generate_recovery_codes(user)
    assert secret  # sanity — totp is what makes recovery_code eligible here

    pending_token = _pending_token(user)
    with pytest.raises(ChallengeInvalid):
        TwoFactorService.verify_second_factor(pending_token, method="recovery_code")

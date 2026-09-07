"""Proves ``services.TwoFactorService``'s Phase 7 methods — ``enroll_totp``, ``confirm_totp``,
``disable``, ``admin_force_disable``, ``generate_recovery_codes``, ``resolve_pending`` — against
real ``pyotp``/``appkit.crypto.Cipher`` calls, not mocks. ``eligible_methods`` (Phase 6) already
has its own dedicated file, ``test_two_factor_eligibility.py``; ``verify_second_factor`` has its
own, ``test_two_factor_verify.py``. Every stored secret here is proven hashed/encrypted at rest by
an actual database-row inspection, not by reading the model/service code that claims it
(definition-of-done requirement).
"""

from __future__ import annotations

import pytest
from appkit.crypto import Cipher
from django.core.exceptions import ValidationError
from django.test import override_settings
from django.utils import timezone

from jwt_multiauth import keys, otp
from jwt_multiauth.factories import (
    RecoveryCodeFactory,
    TrustedDeviceFactory,
    TwoFactorDeviceFactory,
    UserFactory,
    VerifiedContactFactory,
)
from jwt_multiauth.models import RecoveryCode, TwoFactorDevice, VerifiedContact
from jwt_multiauth.services import InvalidPendingToken, TokenService, TwoFactorService

#: A hard `import pyotp` at module scope would crash collection under the bare-install leg
#: (`make test-bare`) BEFORE `pytestmark`'s `requires_extra` marker ever gets a chance to
#: deselect anything — marker filtering only applies to already-collected tests.
#: `importorskip` converts that would-be collection error into a clean whole-module skip instead.
pyotp = pytest.importorskip("pyotp")

pytestmark = [pytest.mark.django_db, pytest.mark.requires_extra]


def _current_totp_code(secret: str) -> str:
    return pyotp.TOTP(secret).now()


# ------------------------------------------------------------------------------- enroll_totp


def test_enroll_totp_returns_the_plaintext_secret_and_an_otpauth_uri() -> None:
    user = UserFactory(username="alice")
    enrollment = TwoFactorService.enroll_totp(user)

    assert len(enrollment.secret) >= 16  # pyotp.random_base32()'s default length
    assert enrollment.otpauth_uri.startswith("otpauth://totp/")
    assert enrollment.secret in enrollment.otpauth_uri


@override_settings(JWT_MULTIAUTH={"TWO_FACTOR": {"TOTP_ISSUER": "Acme"}})
def test_enroll_totp_embeds_the_configured_issuer() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    assert "issuer=Acme" in enrollment.otpauth_uri


def test_enroll_totp_omits_issuer_when_unconfigured() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    assert "issuer=" not in enrollment.otpauth_uri


def test_enroll_totp_creates_an_unconfirmed_device_row() -> None:
    user = UserFactory()
    TwoFactorService.enroll_totp(user)
    device = TwoFactorDevice.objects.get(user=user, method="totp")
    assert device.confirmed_at is None
    assert device.disabled_at is None
    assert device.last_used_step == 0


def test_enroll_totp_secret_is_encrypted_at_rest_proven_by_row_inspection() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)

    row = TwoFactorDevice.objects.get(user=user, method="totp")
    assert row.secret_encrypted != enrollment.secret
    assert enrollment.secret not in row.secret_encrypted
    decrypted = Cipher(keys.get_encryption_key()).decrypt(row.secret_encrypted)
    assert decrypted == enrollment.secret


def test_enroll_totp_silently_replaces_a_prior_unconfirmed_enrollment() -> None:
    user = UserFactory()
    first = TwoFactorService.enroll_totp(user)
    second = TwoFactorService.enroll_totp(user)

    assert first.secret != second.secret
    assert TwoFactorDevice.objects.filter(user=user, method="totp").count() == 1
    row = TwoFactorDevice.objects.get(user=user, method="totp")
    assert Cipher(keys.get_encryption_key()).decrypt(row.secret_encrypted) == second.secret


def test_enroll_totp_replaces_a_prior_disabled_device_and_it_is_no_longer_disabled() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=_current_totp_code(enrollment.secret))
    TwoFactorService.disable(user, method="totp")
    assert TwoFactorDevice.objects.get(user=user, method="totp").disabled_at is not None

    new_enrollment = TwoFactorService.enroll_totp(user)
    device = TwoFactorDevice.objects.get(user=user, method="totp")
    assert device.disabled_at is None
    assert device.confirmed_at is None
    decrypted = Cipher(keys.get_encryption_key()).decrypt(device.secret_encrypted)
    assert decrypted == new_enrollment.secret


# ------------------------------------------------------------------------------ confirm_totp


def test_confirm_totp_happy_path_sets_confirmed_at() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=_current_totp_code(enrollment.secret))

    device = TwoFactorDevice.objects.get(user=user, method="totp")
    assert device.confirmed_at is not None
    assert device.last_used_step > 0


def test_confirm_totp_rejects_a_wrong_code() -> None:
    user = UserFactory()
    TwoFactorService.enroll_totp(user)
    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.confirm_totp(user, code="000000")
    assert excinfo.value.code == "invalid_totp_code"


def test_confirm_totp_rejects_with_no_pending_enrollment_at_all() -> None:
    user = UserFactory()
    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.confirm_totp(user, code="000000")
    assert excinfo.value.code == "no_pending_totp_enrollment"


def test_confirm_totp_rejects_an_already_confirmed_device() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=_current_totp_code(enrollment.secret))

    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.confirm_totp(user, code=_current_totp_code(enrollment.secret))
    assert excinfo.value.code == "totp_already_confirmed"


# ----------------------------------------------------------------------------------- disable


def test_disable_totp_sets_disabled_at() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=_current_totp_code(enrollment.secret))

    TwoFactorService.disable(user, method="totp")
    device = TwoFactorDevice.objects.get(user=user, method="totp")
    assert device.disabled_at is not None


def test_disable_totp_raises_when_nothing_confirmed_to_disable() -> None:
    user = UserFactory()
    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.disable(user, method="totp")
    assert excinfo.value.code == "method_not_enrolled"


def test_disable_recovery_code_deletes_unused_rows() -> None:
    user = UserFactory()
    RecoveryCodeFactory.create_batch(3, user=user)
    TwoFactorService.disable(user, method="recovery_code")
    assert not RecoveryCode.objects.filter(user=user).exists()


def test_disable_recovery_code_raises_when_none_unused() -> None:
    user = UserFactory()
    RecoveryCodeFactory(user=user, used_at=timezone.now())
    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.disable(user, method="recovery_code")
    assert excinfo.value.code == "method_not_enrolled"


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_disable_email_otp_deletes_the_verified_contact_row() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")

    TwoFactorService.disable(user, method="email_otp")
    assert not VerifiedContact.objects.filter(user=user, field="email").exists()


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_disable_email_otp_raises_when_not_verified() -> None:
    user = UserFactory(email="alice@example.com")
    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.disable(user, method="email_otp")
    assert excinfo.value.code == "method_not_enrolled"


def test_disable_unknown_method_raises() -> None:
    user = UserFactory()
    with pytest.raises(ValidationError) as excinfo:
        TwoFactorService.disable(user, method="not-a-real-method")
    assert excinfo.value.code == "unknown_method"


# --------------------------------------------------------------------------- admin_force_disable


def test_admin_force_disable_disables_confirmed_totp_and_deletes_unused_recovery_codes() -> None:
    user = UserFactory()
    enrollment = TwoFactorService.enroll_totp(user)
    TwoFactorService.confirm_totp(user, code=_current_totp_code(enrollment.secret))
    RecoveryCodeFactory.create_batch(2, user=user)
    used_code = RecoveryCodeFactory(user=user, used_at=timezone.now())

    TwoFactorService.admin_force_disable(user)

    assert TwoFactorDevice.objects.get(user=user, method="totp").disabled_at is not None
    assert not RecoveryCode.objects.filter(user=user, used_at__isnull=True).exists()
    # a previously-used code is left alone — force-disable only clears LIVE codes.
    assert RecoveryCode.objects.filter(pk=used_code.pk).exists()


def test_admin_force_disable_revokes_every_live_trusted_device() -> None:
    user = UserFactory()
    live = TrustedDeviceFactory(user=user, token_hash="1" * 64)
    already_revoked = TrustedDeviceFactory(
        user=user, token_hash="2" * 64, revoked_at=timezone.now()
    )

    TwoFactorService.admin_force_disable(user)

    live.refresh_from_db()
    already_revoked.refresh_from_db()
    assert live.revoked_at is not None
    assert already_revoked.revoked_at is not None  # untouched, already revoked


@override_settings(JWT_MULTIAUTH={"USER_FIELDS": {"EMAIL_FIELD": "email"}})
def test_admin_force_disable_does_not_touch_verified_contact() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")

    TwoFactorService.admin_force_disable(user)

    assert VerifiedContact.objects.filter(user=user, field="email").exists()


def test_admin_force_disable_on_a_bare_account_is_a_no_op_not_an_error() -> None:
    user = UserFactory()
    TwoFactorService.admin_force_disable(user)  # must not raise


# ---------------------------------------------------------------------- generate_recovery_codes


@override_settings(JWT_MULTIAUTH={"TWO_FACTOR": {"RECOVERY_CODE_COUNT": 6}})
def test_generate_recovery_codes_returns_the_configured_count_of_plaintext_codes() -> None:
    user = UserFactory()
    codes = TwoFactorService.generate_recovery_codes(user)
    assert len(codes) == 6
    assert len(set(codes)) == 6  # no accidental duplicates


def test_generate_recovery_codes_deletes_prior_unused_codes() -> None:
    user = UserFactory()
    stale = RecoveryCodeFactory(user=user)
    TwoFactorService.generate_recovery_codes(user)
    assert not RecoveryCode.objects.filter(pk=stale.pk).exists()


def test_generate_recovery_codes_leaves_prior_used_codes_alone() -> None:
    user = UserFactory()
    used = RecoveryCodeFactory(user=user, used_at=timezone.now())
    TwoFactorService.generate_recovery_codes(user)
    assert RecoveryCode.objects.filter(pk=used.pk).exists()


def test_generate_recovery_codes_are_hashed_at_rest_proven_by_row_inspection() -> None:
    user = UserFactory()
    codes = TwoFactorService.generate_recovery_codes(user)
    pepper = keys.get_otp_pepper()

    rows = list(RecoveryCode.objects.filter(user=user))
    assert len(rows) == len(codes)
    for row in rows:
        assert len(row.code_hash) == 64
        assert row.code_hash not in codes
        assert any(otp.verify_secret(code, row.code_hash, pepper=pepper) for code in codes)


# ----------------------------------------------------------------------------- resolve_pending


def test_resolve_pending_returns_the_user_claims_and_eligible_methods() -> None:
    user = UserFactory()
    TwoFactorDeviceFactory(user=user, method="totp")
    pending_token = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta={"ip": "203.0.113.5"}
    )

    resolved_user, claims, eligible = TwoFactorService.resolve_pending(pending_token)
    assert resolved_user.pk == user.pk
    assert claims["primary_method"] == "password"
    assert eligible == ["totp"]


def test_resolve_pending_raises_invalid_pending_token_for_garbage() -> None:
    with pytest.raises(InvalidPendingToken):
        TwoFactorService.resolve_pending("not-a-real-token")


def test_resolve_pending_raises_invalid_pending_token_when_user_no_longer_resolves() -> None:
    user = UserFactory()
    pending_token = TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta={"ip": "203.0.113.5"}
    )
    user.delete()

    with pytest.raises(InvalidPendingToken):
        TwoFactorService.resolve_pending(pending_token)

"""Proves ``services.TwoFactorService.eligible_methods`` (Phase 6's own partial landing of
``TwoFactorService`` — see ``docs/CONTRACT.md`` §11's Phase 6 deviations register): the
intersection of ``TWO_FACTOR["ALLOWED_METHODS"]`` and actually-enrolled methods, the
different-channel filter, and the hard constraint that ``["recovery_code"]`` is never returned
alone (``docs/CONTRACT.md`` §11 item 14).
"""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.utils import timezone

from jwt_multiauth.factories import (
    RecoveryCodeFactory,
    TwoFactorDeviceFactory,
    UserFactory,
    VerifiedContactFactory,
)
from jwt_multiauth.services import TwoFactorService

pytestmark = pytest.mark.django_db


def _two_factor_settings(**overrides: object) -> dict[str, object]:
    return {"USER_FIELDS": {"EMAIL_FIELD": "email"}, "TWO_FACTOR": overrides}


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp"]))
def test_no_enrollment_at_all_is_never_eligible() -> None:
    user = UserFactory()
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == []


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp"]))
def test_confirmed_totp_device_is_eligible() -> None:
    user = UserFactory()
    TwoFactorDeviceFactory(user=user, method="totp")  # confirmed_at set by the factory default
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == ["totp"]


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp"]))
def test_unconfirmed_totp_device_is_not_eligible() -> None:
    user = UserFactory()
    TwoFactorDeviceFactory(user=user, method="totp", confirmed_at=None)
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == []


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp"]))
def test_disabled_totp_device_is_not_eligible() -> None:
    user = UserFactory()
    TwoFactorDeviceFactory(user=user, method="totp", disabled_at=timezone.now())
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == []


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp"]))
def test_totp_not_offered_when_not_in_allowed_methods() -> None:
    # ALLOWED_METHODS above doesn't include "totp"'s replacement — re-override to something else.
    with override_settings(
        JWT_MULTIAUTH={
            "USER_FIELDS": {"EMAIL_FIELD": "email"},
            "TWO_FACTOR": {"ALLOWED_METHODS": ["email_otp"]},
        }
    ):
        user = UserFactory(email="alice@example.com")
        TwoFactorDeviceFactory(user=user, method="totp")
        VerifiedContactFactory(user=user, field="email", value="alice@example.com")
        assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == [
            "email_otp"
        ]


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["email_otp"]))
def test_email_otp_eligible_when_verified_contact_matches_current_value() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == ["email_otp"]


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["email_otp"]))
def test_email_otp_not_eligible_when_verified_contact_is_stale() -> None:
    # The user's live email changed since verification — "effectively unverified again"
    # (models.VerifiedContact's own resolution rule).
    user = UserFactory(email="alice-new@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice-old@example.com")
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == []


@override_settings(
    JWT_MULTIAUTH=_two_factor_settings(
        ALLOWED_METHODS=["email_otp"], REQUIRE_DIFFERENT_CHANNEL=True
    )
)
def test_different_channel_rule_drops_a_method_matching_the_primary_channel() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    # Logged in via email_otp itself — email_otp can't also serve as its own second factor.
    assert TwoFactorService.eligible_methods(user, used_primary_channel="email") == []


@override_settings(
    JWT_MULTIAUTH=_two_factor_settings(
        ALLOWED_METHODS=["email_otp"], REQUIRE_DIFFERENT_CHANNEL=True
    )
)
def test_different_channel_rule_never_drops_password_channel_methods() -> None:
    # Password is its own channel — 2FA via email is fully eligible after a password login.
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == ["email_otp"]


@override_settings(
    JWT_MULTIAUTH=_two_factor_settings(
        ALLOWED_METHODS=["email_otp"], REQUIRE_DIFFERENT_CHANNEL=False
    )
)
def test_different_channel_rule_disabled_keeps_the_same_channel_method() -> None:
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    assert TwoFactorService.eligible_methods(user, used_primary_channel="email") == ["email_otp"]


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["recovery_code"]))
def test_recovery_code_is_never_returned_alone() -> None:
    """docs/CONTRACT.md §11 item 14's hard constraint: an unused RecoveryCode existing is not
    enough by itself — recovery codes are never the ONLY offered second factor.
    """
    user = UserFactory()
    RecoveryCodeFactory(user=user)
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == []


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp", "recovery_code"]))
def test_recovery_code_is_eligible_alongside_a_real_method() -> None:
    user = UserFactory()
    TwoFactorDeviceFactory(user=user, method="totp")
    RecoveryCodeFactory(user=user)
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == [
        "totp",
        "recovery_code",
    ]


@override_settings(JWT_MULTIAUTH=_two_factor_settings(ALLOWED_METHODS=["totp", "recovery_code"]))
def test_recovery_code_not_eligible_when_all_codes_are_used() -> None:
    user = UserFactory()
    TwoFactorDeviceFactory(user=user, method="totp")
    RecoveryCodeFactory(user=user, used_at=timezone.now())
    assert TwoFactorService.eligible_methods(user, used_primary_channel="password") == ["totp"]


@override_settings(
    JWT_MULTIAUTH=_two_factor_settings(
        ALLOWED_METHODS=["email_otp", "recovery_code"], REQUIRE_DIFFERENT_CHANNEL=True
    )
)
def test_recovery_code_not_reintroduced_after_different_channel_strips_the_only_real_method() -> (
    None
):
    """Proves the recovery-code step runs AFTER the different-channel filter, not before: if it
    ran first, the different-channel filter would strip email_otp and leave ["recovery_code"]
    behind on its own — exactly the invariant this test guards.
    """
    user = UserFactory(email="alice@example.com")
    VerifiedContactFactory(user=user, field="email", value="alice@example.com")
    RecoveryCodeFactory(user=user)
    assert TwoFactorService.eligible_methods(user, used_primary_channel="email") == []

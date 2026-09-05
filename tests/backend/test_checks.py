"""Proves every ``jwt_multiauth.checks`` ID fires under the exact condition that should trigger
it, and only then — the zero-config default (``ALLOWED_AUTH_METHODS = ["password"]``,
``TWO_FACTOR["POLICY"] = "off"``) must return ``[]`` from every one of them.
"""

from __future__ import annotations

from unittest import mock

from django.test import override_settings

from jwt_multiauth import checks


def test_zero_config_default_is_clean() -> None:
    assert checks.check_user_field_requirements(None) == []
    assert checks.check_totp_requirements(None) == []
    assert checks.check_allowed_methods_closed_set(None) == []
    assert checks.check_unknown_settings_keys(None) == []


@override_settings(JWT_MULTIAUTH={"ALLOWED_AUTH_METHODS": ["password", "phone_otp"]})
def test_e001_fires_when_active_method_field_unset() -> None:
    errors = checks.check_user_field_requirements(None)
    assert any(e.id == "jwt_multiauth.E001" for e in errors)


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "phone_otp"],
        "USER_FIELDS": {"PHONE_FIELD": "does_not_exist_on_user"},
    }
)
def test_e002_fires_when_named_field_does_not_exist() -> None:
    errors = checks.check_user_field_requirements(None)
    assert any(e.id == "jwt_multiauth.E002" for e in errors)


@override_settings(
    JWT_MULTIAUTH={
        "ALLOWED_AUTH_METHODS": ["password", "email_otp"],
        "USER_FIELDS": {"EMAIL_FIELD": "email"},
    }
)
def test_e003_fires_for_non_unique_field_stock_user_email() -> None:
    # django.contrib.auth.User.email is not unique by default — exactly the case this repo's
    # CLAUDE.md rule 3 documents as the expected E003 trigger.
    errors = checks.check_user_field_requirements(None)
    assert any(e.id == "jwt_multiauth.E003" for e in errors)


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "opt_in", "ALLOWED_METHODS": ["totp"]}},
    JWT_MULTIAUTH_ENCRYPTION_KEY=None,
)
def test_e004_fires_when_totp_active_and_encryption_key_unset() -> None:
    errors = checks.check_totp_requirements(None)
    assert any(e.id == "jwt_multiauth.E004" for e in errors)


def test_totp_requirements_are_not_checked_when_policy_is_off() -> None:
    # Default TWO_FACTOR.ALLOWED_METHODS already contains "totp", but POLICY defaults to "off" —
    # this must impose NO requirement at all (docs/CONTRACT.md §11 item 16's POLICY gate).
    errors = checks.check_totp_requirements(None)
    assert errors == []


@override_settings(
    JWT_MULTIAUTH={"TWO_FACTOR": {"POLICY": "opt_in", "ALLOWED_METHODS": ["totp"]}},
    JWT_MULTIAUTH_ENCRYPTION_KEY="a-real-looking-key",
)
def test_e005_fires_when_totp_extra_not_importable() -> None:
    with mock.patch.dict("sys.modules", {"pyotp": None}):
        errors = checks.check_totp_requirements(None)
    assert any(e.id == "jwt_multiauth.E005" for e in errors)


@override_settings(JWT_MULTIAUTH={"ALLOWED_AUTH_METHODS": ["password", "not_a_real_method"]})
def test_e006_fires_for_unrecognised_login_method() -> None:
    errors = checks.check_allowed_methods_closed_set(None)
    assert any(e.id == "jwt_multiauth.E006" for e in errors)


@override_settings(JWT_MULTIAUTH={"TWO_FACTOR": {"ALLOWED_METHODS": ["not_a_real_method"]}})
def test_e006_fires_for_unrecognised_two_factor_method() -> None:
    errors = checks.check_allowed_methods_closed_set(None)
    assert any(e.id == "jwt_multiauth.E006" for e in errors)


@override_settings(JWT_MULTIAUTH={"NOT_A_REAL_TOP_LEVEL_KEY": True})
def test_w001_fires_for_unknown_top_level_key() -> None:
    warnings = checks.check_unknown_settings_keys(None)
    assert any(w.id == "jwt_multiauth.W001" for w in warnings)

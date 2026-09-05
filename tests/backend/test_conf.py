"""Proves ``jwt_multiauth.conf``'s nested-merge behavior and the OTP resolution chain
(purpose -> channel -> ``OTP["DEFAULTS"]``) — the property the rest of this app's settings access
rests on entirely.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from jwt_multiauth import conf


def test_get_setting_returns_documented_default_with_no_override() -> None:
    assert conf.get_setting("ALLOWED_AUTH_METHODS") == ["password"]
    assert conf.get_setting("TOKENS")["ACCESS_TTL_SECONDS"] == 900


@override_settings(JWT_MULTIAUTH={"TOKENS": {"ACCESS_TTL_SECONDS": 60}})
def test_get_setting_merges_one_key_without_blanking_siblings() -> None:
    tokens = conf.get_setting("TOKENS")
    assert tokens["ACCESS_TTL_SECONDS"] == 60
    assert tokens["REFRESH_TTL_SECONDS"] == 1_209_600
    assert tokens["REMEMBER_ME_TTL_SECONDS"] == 2_592_000
    assert tokens["ALGORITHM"] == "HS256"


@override_settings(JWT_MULTIAUTH={"TWO_FACTOR": {"TRUSTED_DEVICE": {"ENABLED": True}}})
def test_get_setting_merges_two_levels_deep_without_blanking_siblings() -> None:
    two_factor = conf.get_setting("TWO_FACTOR")
    assert two_factor["TRUSTED_DEVICE"]["ENABLED"] is True
    assert two_factor["TRUSTED_DEVICE"]["TTL_SECONDS"] == 2_592_000
    assert two_factor["TRUSTED_DEVICE"]["COOKIE_NAME"] == "jwt_multiauth_td"
    assert two_factor["POLICY"] == "off"
    assert two_factor["ALLOWED_METHODS"] == ["totp"]


def test_get_setting_raises_key_error_on_unknown_key() -> None:
    with pytest.raises(KeyError):
        conf.get_setting("NOT_A_REAL_KEY")


def test_get_otp_setting_default_only() -> None:
    assert conf.get_otp_setting("LENGTH", channel="email") == 6


@override_settings(JWT_MULTIAUTH={"OTP": {"CHANNELS": {"email": {"LENGTH": 8}}}})
def test_get_otp_setting_channel_override_beats_default() -> None:
    assert conf.get_otp_setting("LENGTH", channel="email") == 8
    assert conf.get_otp_setting("LENGTH", channel="phone") == 6


@override_settings(
    JWT_MULTIAUTH={
        "OTP": {
            "CHANNELS": {"email": {"TTL_SECONDS": 100}},
            "PURPOSES": {"password_reset": {"TTL_SECONDS": 900}},
        }
    }
)
def test_get_otp_setting_purpose_override_beats_channel_override() -> None:
    assert conf.get_otp_setting("TTL_SECONDS", channel="email", purpose="password_reset") == 900
    assert conf.get_otp_setting("TTL_SECONDS", channel="email", purpose="login") == 100
    assert conf.get_otp_setting("TTL_SECONDS", channel="phone", purpose="login") == 300


def test_get_otp_setting_raises_on_unknown_key() -> None:
    with pytest.raises(ImproperlyConfigured):
        conf.get_otp_setting("NOT_A_REAL_KEY", channel="email")

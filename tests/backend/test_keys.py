"""Proves ``jwt_multiauth.keys``' HKDF derivation is deterministic, that the signing key and OTP
pepper are cryptographically independent of each other despite sharing a root secret, and — the
one rail that matters most — that ``JWT_MULTIAUTH_ENCRYPTION_KEY`` has NO ``SECRET_KEY``-derived
fallback under any circumstance (this repo's ``CLAUDE.md`` rule 4).
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from jwt_multiauth import keys


def test_signing_key_is_deterministic_for_the_same_secret_key() -> None:
    assert keys.get_signing_key() == keys.get_signing_key()


def test_otp_pepper_is_deterministic_for_the_same_secret_key() -> None:
    assert keys.get_otp_pepper() == keys.get_otp_pepper()


def test_signing_key_and_otp_pepper_are_independent() -> None:
    # Same root secret (settings.SECRET_KEY), distinct HKDF `info` strings -> distinct outputs.
    assert keys.get_signing_key() != keys.get_otp_pepper()


def test_derived_keys_change_when_secret_key_changes() -> None:
    baseline_signing_key = keys.get_signing_key()
    baseline_pepper = keys.get_otp_pepper()

    with override_settings(SECRET_KEY="a-different-root-secret"):
        assert keys.get_signing_key() != baseline_signing_key
        assert keys.get_otp_pepper() != baseline_pepper


@override_settings(JWT_MULTIAUTH_SIGNING_KEY="host-provided-signing-key")
def test_host_configured_signing_key_wins_over_derivation() -> None:
    assert keys.get_signing_key() == "host-provided-signing-key"


@override_settings(JWT_MULTIAUTH_OTP_PEPPER="host-provided-pepper")
def test_host_configured_otp_pepper_wins_over_derivation() -> None:
    assert keys.get_otp_pepper() == "host-provided-pepper"


@override_settings(JWT_MULTIAUTH_ENCRYPTION_KEY=None)
def test_encryption_key_raises_when_unset() -> None:
    with pytest.raises(ImproperlyConfigured):
        keys.get_encryption_key()


def test_encryption_key_has_no_secret_key_derived_fallback() -> None:
    """The rail: get_encryption_key() must NEVER silently derive from SECRET_KEY. Proven by
    reading the function's own source for a call into _hkdf_sha256/_root_secret, not merely by
    asserting it raises when unset (raising when unset is necessary but not sufficient — a
    fallback could still exist on some other branch)."""
    import inspect

    source = inspect.getsource(keys.get_encryption_key)
    assert "_hkdf_sha256" not in source
    assert "_root_secret" not in source


@override_settings(JWT_MULTIAUTH_ENCRYPTION_KEY="a-real-fernet-key")
def test_encryption_key_returns_host_configured_value() -> None:
    assert keys.get_encryption_key() == "a-real-fernet-key"

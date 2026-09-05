"""Proves ``jwt_multiauth.tokens``: the full claim set on every issued token, a fresh ``jti`` per
call unless the caller supplies one, one distinctly-named exception per failure mode (expired, bad
signature, malformed, wrong ``typ``), and that ``TOKENS["ALGORITHM"]``/
``JWT_MULTIAUTH_VERIFYING_KEY`` are actually consulted rather than hardcoded.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest
from django.test import override_settings
from freezegun import freeze_time

from jwt_multiauth import tokens

ALL_TYPES = [tokens.TYP_ACCESS, tokens.TYP_REFRESH, tokens.TYP_PENDING_2FA]


@pytest.mark.parametrize("typ", ALL_TYPES)
def test_issue_sets_the_full_claim_set(typ: str) -> None:
    token = tokens.issue({"sub": "1"}, typ=typ, ttl_seconds=60)
    claims = tokens.decode(token, expected_typ=typ)
    assert claims["sub"] == "1"
    assert claims["typ"] == typ
    assert {"iat", "nbf", "exp", "jti"} <= claims.keys()


def test_issue_generates_a_fresh_jti_per_call() -> None:
    first = tokens.decode(
        tokens.issue({"sub": "1"}, typ=tokens.TYP_ACCESS, ttl_seconds=60),
        expected_typ=tokens.TYP_ACCESS,
    )
    second = tokens.decode(
        tokens.issue({"sub": "1"}, typ=tokens.TYP_ACCESS, ttl_seconds=60),
        expected_typ=tokens.TYP_ACCESS,
    )
    assert first["jti"] != second["jti"]


def test_issue_preserves_a_caller_supplied_jti() -> None:
    token = tokens.issue(
        {"sub": "1", "jti": "caller-chosen-jti"}, typ=tokens.TYP_REFRESH, ttl_seconds=60
    )
    claims = tokens.decode(token, expected_typ=tokens.TYP_REFRESH)
    assert claims["jti"] == "caller-chosen-jti"


@pytest.mark.parametrize("issued_as", ALL_TYPES)
@pytest.mark.parametrize("expected_as", ALL_TYPES)
def test_decode_enforces_typ_for_every_pairing(issued_as: str, expected_as: str) -> None:
    token = tokens.issue({"sub": "1"}, typ=issued_as, ttl_seconds=60)
    if issued_as == expected_as:
        tokens.decode(token, expected_typ=expected_as)  # must not raise
    else:
        with pytest.raises(tokens.TokenTypeMismatch):
            tokens.decode(token, expected_typ=expected_as)


def test_decode_rejects_a_tampered_signature() -> None:
    token = tokens.issue({"sub": "1"}, typ=tokens.TYP_ACCESS, ttl_seconds=60)
    header, payload, signature = token.split(".")
    # Flip the FIRST character, never the last: base64url's final character in a
    # non-multiple-of-4 encoding carries a couple of "don't care" low bits, so some flips there
    # decode to the identical byte and leave the signature untouched — flaky roughly 1 run in 16.
    # Every other position is a full 6-bit symbol with no such ambiguity.
    flipped_first_char = "A" if signature[0] != "A" else "B"
    tampered = f"{header}.{payload}.{flipped_first_char}{signature[1:]}"

    with pytest.raises(tokens.TokenSignatureInvalid):
        tokens.decode(tampered, expected_typ=tokens.TYP_ACCESS)


def test_decode_rejects_garbage() -> None:
    with pytest.raises(tokens.TokenMalformed):
        tokens.decode("not-a-jwt-at-all", expected_typ=tokens.TYP_ACCESS)


def test_decode_raises_expired_after_ttl_elapses() -> None:
    with freeze_time("2026-01-01 00:00:00"):
        token = tokens.issue({"sub": "1"}, typ=tokens.TYP_ACCESS, ttl_seconds=60)

    with freeze_time("2026-01-01 00:01:01"), pytest.raises(tokens.TokenExpired):
        tokens.decode(token, expected_typ=tokens.TYP_ACCESS)


@override_settings(JWT_MULTIAUTH={"TOKENS": {"ALGORITHM": "HS384"}})
def test_algorithm_is_read_from_conf_not_hardcoded() -> None:
    token = tokens.issue({"sub": "1"}, typ=tokens.TYP_ACCESS, ttl_seconds=60)
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "HS384"
    # decode() must use the same conf-driven algorithm to verify it back, not a hardcoded HS256.
    claims = tokens.decode(token, expected_typ=tokens.TYP_ACCESS)
    assert claims["sub"] == "1"


@override_settings(JWT_MULTIAUTH_VERIFYING_KEY="a-completely-wrong-key-of-decent-length")
def test_verifying_key_is_actually_consulted() -> None:
    # issue() signs with keys.get_signing_key(), which this override never touches. If decode()
    # verified with get_signing_key() too (ignoring get_verifying_key() entirely), this token
    # would still verify fine — it only fails because decode() reads the DIFFERENT, overridden
    # JWT_MULTIAUTH_VERIFYING_KEY instead.
    token = tokens.issue({"sub": "1"}, typ=tokens.TYP_ACCESS, ttl_seconds=60)
    with pytest.raises(tokens.TokenSignatureInvalid):
        tokens.decode(token, expected_typ=tokens.TYP_ACCESS)

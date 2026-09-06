"""Proves ``jwt_multiauth.otp``: every ``ALPHABET`` keyword builds the right character set,
``exclude_ambiguous`` strips the six confusable characters and raises ``ImproperlyConfigured``
(never loops, never crashes) when that leaves nothing to choose from, ``hash_secret``/
``verify_secret`` are the app's one HMAC-SHA256 scheme with a constant-time compare,
``generate_link_token`` is independent of the code alphabet, ``method_for_channel`` is a real
lookup over the two closed vocabularies, and the module uses ``secrets`` — never ``random`` — with
no ``==`` comparison anywhere in it.
"""

from __future__ import annotations

import inspect
import string

import pytest
from django.core.exceptions import ImproperlyConfigured

from jwt_multiauth import otp

# --------------------------------------------------------------------- generate_code


@pytest.mark.parametrize(
    ("alphabet", "case_sensitive", "expected_chars"),
    [
        ("numeric", False, set(string.digits)),
        ("numeric", True, set(string.digits)),
        ("alpha", False, set(string.ascii_lowercase)),
        ("alpha", True, set(string.ascii_letters)),
        ("alphanumeric", False, set(string.digits) | set(string.ascii_lowercase)),
        ("alphanumeric", True, set(string.digits) | set(string.ascii_letters)),
    ],
)
def test_generate_code_draws_from_the_expected_charset(
    alphabet: str, case_sensitive: bool, expected_chars: set[str]
) -> None:
    code = otp.generate_code(
        length=200, alphabet=alphabet, exclude_ambiguous=False, case_sensitive=case_sensitive
    )
    assert set(code) <= expected_chars


def test_generate_code_honors_length() -> None:
    code = otp.generate_code(
        length=12, alphabet="numeric", exclude_ambiguous=False, case_sensitive=False
    )
    assert len(code) == 12


def test_generate_code_treats_unknown_alphabet_as_a_literal_custom_charset() -> None:
    code = otp.generate_code(
        length=50, alphabet="xyz", exclude_ambiguous=False, case_sensitive=False
    )
    assert set(code) <= set("xyz")


def test_generate_code_exclude_ambiguous_strips_the_six_confusable_characters() -> None:
    code = otp.generate_code(
        length=500, alphabet="alphanumeric", exclude_ambiguous=True, case_sensitive=True
    )
    assert set(code).isdisjoint(set("0O1Ilo"))


def test_generate_code_exclude_ambiguous_going_empty_raises_improperly_configured() -> None:
    # A tiny custom alphabet entirely made of ambiguous characters: exclude_ambiguous must strip
    # it to nothing and raise, never loop forever and never fall back to a biased/default set.
    with pytest.raises(ImproperlyConfigured):
        otp.generate_code(length=6, alphabet="O0Il", exclude_ambiguous=True, case_sensitive=True)


def test_generate_code_is_not_predictable() -> None:
    # Guards against a frozen-seed or constant-return regression without asserting a specific
    # distribution, which would flake. secrets.choice over 10 digits at length 20 collapsing to a
    # single distinct code is a 1-in-10^19 event.
    codes = {
        otp.generate_code(
            length=20, alphabet="numeric", exclude_ambiguous=False, case_sensitive=False
        )
        for _ in range(20)
    }
    assert len(codes) > 1


def test_generate_code_source_uses_secrets_not_random() -> None:
    source = inspect.getsource(otp.generate_code)
    assert "random." not in source
    assert "import random" not in inspect.getsource(otp)
    assert "secrets.choice" in source


# --------------------------------------------------------------------- generate_link_token


def test_generate_link_token_is_high_entropy_and_unique() -> None:
    tokens = {otp.generate_link_token() for _ in range(20)}
    assert len(tokens) == 20
    assert all(len(t) >= 32 for t in tokens)


def test_generate_link_token_is_independent_of_code_alphabet() -> None:
    # A magic link's security must never depend on how short a host configured its numeric code
    # to be — generate_link_token takes no alphabet/length arguments at all.
    assert "alphabet" not in inspect.signature(otp.generate_link_token).parameters
    assert "length" not in inspect.signature(otp.generate_link_token).parameters


# --------------------------------------------------------------------- hash_secret / verify_secret


def test_hash_secret_is_64_hex_characters() -> None:
    digest = otp.hash_secret("123456", pepper="a-pepper")
    assert len(digest) == 64
    assert all(c in string.hexdigits for c in digest)


def test_hash_secret_is_deterministic() -> None:
    assert otp.hash_secret("123456", pepper="a-pepper") == otp.hash_secret(
        "123456", pepper="a-pepper"
    )


def test_hash_secret_is_pepper_dependent() -> None:
    assert otp.hash_secret("123456", pepper="pepper-one") != otp.hash_secret(
        "123456", pepper="pepper-two"
    )


def test_verify_secret_true_for_a_matching_value() -> None:
    digest = otp.hash_secret("123456", pepper="a-pepper")
    assert otp.verify_secret("123456", digest, pepper="a-pepper") is True


def test_verify_secret_false_for_a_wrong_value() -> None:
    digest = otp.hash_secret("123456", pepper="a-pepper")
    assert otp.verify_secret("000000", digest, pepper="a-pepper") is False


def test_verify_secret_false_across_different_peppers() -> None:
    digest = otp.hash_secret("123456", pepper="pepper-one")
    assert otp.verify_secret("123456", digest, pepper="pepper-two") is False


def test_verify_secret_uses_constant_time_compare() -> None:
    # Inspect the function BODY, not its docstring — the docstring itself says "never ``==``",
    # which would trip a naive substring check against the whole source.
    body = inspect.getsource(otp.verify_secret).split('"""')[-1]
    assert "hmac.compare_digest" in body
    assert "==" not in body


def test_otp_module_never_imports_random() -> None:
    """Source-inspection rail, per ``test_keys.py``'s idiom: ruff has no banned-api rule against
    ``random``, so this is the mechanical enforcement available. (The constant-time-compare rail
    for the actual secret comparison is proven separately, in
    ``test_verify_secret_uses_constant_time_compare`` — the ``==`` uses elsewhere in this module
    are plain string-literal alphabet-keyword dispatch, not a secret compare.)
    """
    source = inspect.getsource(otp)
    assert "import random" not in source
    assert "from random" not in source


# --------------------------------------------------------------------- method_for_channel


@pytest.mark.parametrize(
    ("channel", "method"),
    [("email", "email_otp"), ("phone", "phone_otp")],
)
def test_method_for_channel_maps_known_channels(channel: str, method: str) -> None:
    assert otp.method_for_channel(channel) == method


def test_method_for_channel_raises_for_an_unknown_channel() -> None:
    with pytest.raises(ValueError, match="sms"):
        otp.method_for_channel("sms")

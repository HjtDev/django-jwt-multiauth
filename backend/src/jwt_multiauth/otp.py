"""Pure functions, no database access: code/token generation and secret hashing.

Phase 4 implements ``generate_code``, ``generate_link_token``, ``hash_secret``, and
``verify_secret`` — the ONE hashing scheme (HMAC-SHA256, keyed with
``jwt_multiauth.keys.get_otp_pepper()``, compared with ``hmac.compare_digest``, never ``==``) for
every OTP code, link token, recovery code, and trusted-device token in this app
(``docs/CONTRACT.md`` §10). Every generated code/token uses the ``secrets`` module, never
``random`` (this repo's ``CLAUDE.md`` rule 4).

``generate_code`` takes its shape (``length``, ``alphabet``, ``exclude_ambiguous``,
``case_sensitive``) as keyword arguments — it never reads settings itself, staying a pure
function; the caller (``services.OtpService``) is the one that resolves these via
``conf.get_otp_setting(...)``. It raises ``django.core.exceptions.ImproperlyConfigured`` if the
resolved alphabet is empty (e.g. a custom ``alphabet`` string with every character excluded by
``exclude_ambiguous``), per this repo's fail-closed rule — never a loop, never a biased fallback.

``hash_secret``/``verify_secret`` take the pepper as a keyword argument too — ``keys.py`` is never
imported here, so this module has zero settings/database coupling of any kind.

``method_for_channel`` translates between this app's two closed vocabularies: an
``OtpChallenge.channel`` value (``"email"``/``"phone"``) and an auth-method string
(``"email_otp"``/``"phone_otp"``) used by ``ALLOWED_AUTH_METHODS``/``AUTO_PROVISION_METHODS``/
``TWO_FACTOR["ALLOWED_METHODS"]``. The two vocabularies are not the same string, so this is a real
lookup, not an f-string — and it fails closed on an unrecognized channel rather than silently
building a method string nothing in the closed sets will ever match.
"""

from __future__ import annotations

import hmac
import secrets
import string
from typing import Final

from django.core.exceptions import ImproperlyConfigured

#: Characters that are easily confused with one another when read aloud or typed on a phone
#: keypad — dropped from the resulting charset when ``exclude_ambiguous=True`` (docs/CONTRACT.md
#: §2). Deliberately NOT configurable, same rationale as the hash algorithm itself.
_AMBIGUOUS: Final[frozenset[str]] = frozenset("0O1Ilo")

_NUMERIC: Final[str] = string.digits

_CHANNEL_TO_METHOD: Final[dict[str, str]] = {
    "email": "email_otp",
    "phone": "phone_otp",
}


def generate_code(
    *, length: int, alphabet: str, exclude_ambiguous: bool, case_sensitive: bool
) -> str:
    """Generate an OTP code using ``secrets.choice`` over a character set built from
    ``alphabet``:

    - ``"numeric"`` -> ``"0123456789"``.
    - ``"alpha"`` -> ASCII letters, lowercase only unless ``case_sensitive``.
    - ``"alphanumeric"`` -> both of the above combined.
    - anything else -> treated as a literal custom character set, used as given.

    ``exclude_ambiguous`` strips :data:`_AMBIGUOUS` from whatever set results, THEN the
    remaining set is validated non-empty. A host whose custom ``alphabet`` + ``exclude_ambiguous``
    combination leaves nothing to choose from gets ``ImproperlyConfigured`` naming the exact
    setting combination — fail at first use, never an infinite loop, never a silently biased
    fallback alphabet.
    """
    if alphabet == "numeric":
        charset = _NUMERIC
    elif alphabet == "alpha":
        charset = string.ascii_letters if case_sensitive else string.ascii_lowercase
    elif alphabet == "alphanumeric":
        letters = string.ascii_letters if case_sensitive else string.ascii_lowercase
        charset = _NUMERIC + letters
    else:
        charset = alphabet

    if exclude_ambiguous:
        charset = "".join(ch for ch in charset if ch not in _AMBIGUOUS)

    if not charset:
        raise ImproperlyConfigured(
            f"jwt_multiauth.otp.generate_code() resolved an empty character set for "
            f"alphabet={alphabet!r}, exclude_ambiguous={exclude_ambiguous!r}, "
            f"case_sensitive={case_sensitive!r} — every character was excluded as ambiguous. "
            f"Widen OTP['ALPHABET'] or set OTP['EXCLUDE_AMBIGUOUS'] to False."
        )

    return "".join(secrets.choice(charset) for _ in range(length))


def generate_link_token() -> str:
    """A high-entropy magic-link token, independent of the code's own alphabet — a magic link's
    security must never depend on how short a host configured its numeric code to be.
    """
    return secrets.token_urlsafe(32)


def hash_secret(value: str, *, pepper: str) -> str:
    """HMAC-SHA256(key=pepper, msg=value), hexdigest. The ONE hashing scheme for every OTP code,
    link token, recovery code, and trusted-device token in this app — no second scheme anywhere.
    """
    return hmac.new(pepper.encode(), value.encode(), "sha256").hexdigest()


def verify_secret(value: str, expected_hash: str, *, pepper: str) -> bool:
    """Recompute ``value``'s hash and compare against ``expected_hash`` with
    ``hmac.compare_digest`` — never ``==``.
    """
    return hmac.compare_digest(hash_secret(value, pepper=pepper), expected_hash)


def method_for_channel(channel: str) -> str:
    """Map an ``OtpChallenge.channel`` value to its auth-method string
    (``"email"`` -> ``"email_otp"``, ``"phone"`` -> ``"phone_otp"``). Raises ``ValueError`` for
    any other channel — fail closed rather than silently build a method string that can't match
    ``ALLOWED_AUTH_METHODS``/``AUTO_PROVISION_METHODS``/``TWO_FACTOR["ALLOWED_METHODS"]``.
    """
    try:
        return _CHANNEL_TO_METHOD[channel]
    except KeyError:
        raise ValueError(
            f"jwt_multiauth.otp.method_for_channel() got unknown channel {channel!r}."
        ) from None

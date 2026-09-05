"""HKDF derivation for ``JWT_MULTIAUTH_SIGNING_KEY``/``JWT_MULTIAUTH_OTP_PEPPER`` when unset, and
the loud, actionable error for a required-but-absent ``JWT_MULTIAUTH_ENCRYPTION_KEY``.

Four ``.env`` keys, per ``docs/CONTRACT.md`` §6:

* ``JWT_MULTIAUTH_SIGNING_KEY`` — optional. HKDF-derived from ``settings.SECRET_KEY`` when
  unset. Fine as-is for ``HS256`` (this app's default algorithm); a host running ``RS256``
  overrides it with a real private key.
* ``JWT_MULTIAUTH_VERIFYING_KEY`` — optional. Falls back to :func:`get_signing_key` when unset —
  correct for ``HS256``, where one symmetric key both signs and verifies. A host running
  ``RS256`` sets this to the public key matching its ``JWT_MULTIAUTH_SIGNING_KEY`` private key.
* ``JWT_MULTIAUTH_OTP_PEPPER`` — optional. HKDF-derived from ``settings.SECRET_KEY`` when unset,
  with a **different** ``info`` string than the signing key's — the two derived values are
  cryptographically independent of each other despite sharing a root secret. Fed into
  ``otp.hash_secret``/``verify_secret`` as extra HMAC input, independent of the database.
* ``JWT_MULTIAUTH_ENCRYPTION_KEY`` — conditionally required (``checks.check_totp_requirements``'s
  ``jwt_multiauth.E004`` — required only when ``"totp"`` is active). **Never derived from
  ``SECRET_KEY``, under any circumstance** — this repo's ``CLAUDE.md`` rule 4 / this app's own
  §0 item 4: a ``SECRET_KEY`` rotation must never invisibly brick every enrolled authenticator.
  :func:`get_encryption_key` has no fallback branch at all; it either returns the host's own
  configured key or raises, naming the fix.

HKDF (RFC 5869) over SHA-256, implemented on stdlib ``hmac``/``hashlib`` rather than
``cryptography`` — these two derived keys must work on a bare, extras-free install, and
``cryptography`` only ever arrives via the ``totp`` extra.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

#: Fixed, distinct HKDF "info" strings per purpose (RFC 5869 §2.3) — this is what makes the two
#: derived values cryptographically independent of each other even though both are derived from
#: the same root secret (settings.SECRET_KEY). Never change these for an existing deployment:
#: doing so silently rotates the derived key out from under every host that never set its own
#: JWT_MULTIAUTH_SIGNING_KEY/JWT_MULTIAUTH_OTP_PEPPER.
_SIGNING_KEY_INFO: Final[bytes] = b"jwt_multiauth/signing-key/v1"
_OTP_PEPPER_INFO: Final[bytes] = b"jwt_multiauth/otp-pepper/v1"

_HASH_NAME: Final[str] = "sha256"
_OUTPUT_LENGTH: Final[int] = 32  # bytes — matches HMAC-SHA256's own digest size


def _hkdf_sha256(input_key_material: bytes, info: bytes, length: int = _OUTPUT_LENGTH) -> bytes:
    """RFC 5869 HKDF-Extract-then-Expand over SHA-256, with an empty salt (RFC 5869 §2.2:
    an omitted salt is treated as a string of zero-valued bytes, the digest size of the hash
    function). Not part of this module's public surface.
    """
    digest_size = hashlib.new(_HASH_NAME).digest_size
    salt = b"\x00" * digest_size
    pseudorandom_key = hmac.new(salt, input_key_material, _HASH_NAME).digest()

    output = b""
    previous_block = b""
    counter = 1
    while len(output) < length:
        previous_block = hmac.new(
            pseudorandom_key, previous_block + info + bytes([counter]), _HASH_NAME
        ).digest()
        output += previous_block
        counter += 1
    return output[:length]


def _root_secret() -> bytes:
    """``settings.SECRET_KEY`` as bytes — the shared root every derived key comes from. Not part
    of this module's public surface.
    """
    secret_key = settings.SECRET_KEY
    return secret_key.encode() if isinstance(secret_key, str) else secret_key


def get_signing_key() -> str:
    """The JWT signing key: the host's own ``JWT_MULTIAUTH_SIGNING_KEY`` if set, otherwise
    HKDF-derived from ``SECRET_KEY``. A host running ``TOKENS["ALGORITHM"] = "RS256"`` must set
    ``JWT_MULTIAUTH_SIGNING_KEY`` to a real private key — the derived value is only ever
    appropriate for ``HS256``.
    """
    configured = getattr(settings, "JWT_MULTIAUTH_SIGNING_KEY", None)
    if configured:
        return str(configured)
    return _hkdf_sha256(_root_secret(), _SIGNING_KEY_INFO).hex()


def get_verifying_key() -> str:
    """The key ``tokens.decode`` verifies a signature against: the host's own
    ``JWT_MULTIAUTH_VERIFYING_KEY`` if set, otherwise :func:`get_signing_key`. Unlike
    :func:`get_encryption_key`, this one HAS a fallback by design — for ``TOKENS["ALGORITHM"] =
    "HS256"`` (this app's default), the same symmetric key both signs and verifies, so falling
    back to :func:`get_signing_key` is simply correct, not a compromise. A host running
    ``"RS256"`` sets ``JWT_MULTIAUTH_SIGNING_KEY`` to a private key and MUST also set
    ``JWT_MULTIAUTH_VERIFYING_KEY`` to the matching public key — without this function, "RS256-
    ready" would be a lie, since there would be no way to verify with anything other than the
    private key ``get_signing_key`` returns.
    """
    configured = getattr(settings, "JWT_MULTIAUTH_VERIFYING_KEY", None)
    if configured:
        return str(configured)
    return get_signing_key()


def get_otp_pepper() -> str:
    """Extra HMAC input for OTP/recovery-code hashing, independent of the database: the host's
    own ``JWT_MULTIAUTH_OTP_PEPPER`` if set, otherwise HKDF-derived from ``SECRET_KEY`` with a
    different ``info`` string than :func:`get_signing_key` — the two are cryptographically
    independent despite sharing a root secret.
    """
    configured = getattr(settings, "JWT_MULTIAUTH_OTP_PEPPER", None)
    if configured:
        return str(configured)
    return _hkdf_sha256(_root_secret(), _OTP_PEPPER_INFO).hex()


def get_encryption_key() -> str:
    """The Fernet key TOTP-secret encryption is keyed by. **No derivation path exists** — this
    function either returns the host's own ``JWT_MULTIAUTH_ENCRYPTION_KEY`` or raises.

    Raises:
        ImproperlyConfigured: the setting is unset or empty. Naming ``appkit.crypto.generate_key()``
            as the fix — never falling back to a ``SECRET_KEY``-derived value, even as a
            convenience default, by design (this repo's ``CLAUDE.md`` rule 4).
    """
    key = getattr(settings, "JWT_MULTIAUTH_ENCRYPTION_KEY", None)
    if not key:
        raise ImproperlyConfigured(
            "JWT_MULTIAUTH_ENCRYPTION_KEY is not set. This key is required because TOTP is "
            "enabled, and it is NEVER derived from SECRET_KEY, by design — a SECRET_KEY "
            "rotation must never invisibly brick every enrolled authenticator. Generate one "
            "with appkit.crypto.generate_key() and set it in your environment."
        )
    return str(key)

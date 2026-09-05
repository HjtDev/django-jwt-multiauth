"""Data models: ``OtpChallenge``, ``AuthSession``, ``TwoFactorDevice``, ``RecoveryCode``,
``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``.

Phase 2 implements all seven exactly as ``docs/CONTRACT.md`` §1 specifies, with
``Meta.indexes`` on every field used in a frequent filter/ordering/lookup
(``APP-DESIGN.md`` §2's baseline query-optimization note).

Every FK/O2O-shaped reference anywhere in this module is ``settings.AUTH_USER_MODEL`` — never a
concrete user-model import (this repo's ``CLAUDE.md`` rule 1, ``docs/CONTRACT.md`` §0 item 1).
``OtpChallenge.user`` is nullable in the schema but never actually written as ``None`` in
v1.0.0 (``docs/CONTRACT.md`` §11 item 11) — the field allows it structurally so a future purpose
needing an unresolved-user row isn't blocked at the schema level, but no code path in this app
writes a decoy row; the decoy-challenge behavior (rule 5, enumeration resistance) is implemented
without ever persisting one.

Every secret-holding field (an OTP code, a recovery code, a TOTP seed, a refresh/session token)
is a plain ``CharField``/``TextField`` here — hashing (``otp.hash_secret``, HMAC-SHA256 via
``hmac.compare_digest``) and encryption (``appkit.crypto.Cipher``, keyed by
``jwt_multiauth.keys.get_encryption_key()``) happen in ``services.py``, never in a custom field
descriptor (this repo's ``CLAUDE.md`` rule 4).
"""

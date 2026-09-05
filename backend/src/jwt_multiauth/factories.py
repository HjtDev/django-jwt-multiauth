"""``factory_boy`` factories — this app's public *test-only* surface (``APP-DESIGN.md`` §7.3).

Phase 2 onward adds factories for each of the seven models (``OtpChallenge``, ``AuthSession``,
``TwoFactorDevice``, ``RecoveryCode``, ``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``)
as each is defined. A host's own test suite is expected to import from here rather than
hand-rolling equivalents.

This module is ruff-banned from ``src/jwt_multiauth`` (see ``backend/pyproject.toml``'s
``banned-api`` block) — nothing under ``src/`` may import it, since importing test factories from
production code is exactly the mistake that guard exists to catch. The test tree
(``../tests/backend``) is exempted from that ban.
"""

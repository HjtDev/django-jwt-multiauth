"""``factory_boy`` factories — this app's public *test-only* surface (``APP-DESIGN.md`` §7.3).

Phase 2 adds factories for each of the seven models (``OtpChallenge``, ``AuthSession``,
``TwoFactorDevice``, ``RecoveryCode``, ``VerifiedContact``, ``LoginAttempt``, ``TrustedDevice``),
plus a ``UserFactory`` resolving ``get_user_model()`` the same way every other app package's own
``factories.py`` does. A host's own test suite is expected to import from here rather than
hand-rolling equivalents.

Every secret-holding field (``code_hash``, ``link_token_hash``, ``secret_encrypted``,
``token_hash``) gets an obviously-fake, fixed placeholder value — never a real hash/ciphertext,
since this module has no business calling into ``services.py``'s hashing/encryption helpers. Each
is a hex-looking constant the same length a real HMAC-SHA256 digest would be, purely so a test
asserting "this field holds a 64-char hex string" doesn't need special-casing for factory-built
rows; ``# noqa: S105`` mirrors ``throttling.py``'s existing precedent for "this is not a real
secret, ruff's bandit rule just can't tell the difference."

This module is ruff-banned from ``src/jwt_multiauth`` (see ``backend/pyproject.toml``'s
``banned-api`` block) — nothing under ``src/`` may import it, since importing test factories from
production code is exactly the mistake that guard exists to catch. The test tree
(``../tests/backend``) is exempted from that ban.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import factory.django
from django.contrib.auth import get_user_model
from django.utils import timezone
from factory.declarations import LazyFunction, Sequence, SubFactory

from jwt_multiauth.models import (
    AuthSession,
    LoginAttempt,
    OtpChallenge,
    RecoveryCode,
    TrustedDevice,
    TwoFactorDevice,
    VerifiedContact,
)

_FAKE_HASH = "0" * 64


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = get_user_model()
        django_get_or_create = ("username",)

    username = Sequence(lambda n: f"user{n}")


class OtpChallengeFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = OtpChallenge

    challenge_id = LazyFunction(uuid.uuid4)
    user = SubFactory(UserFactory)
    channel = "email"
    purpose = "login"
    destination = Sequence(lambda n: f"user{n}@example.com")
    code_hash = _FAKE_HASH
    link_token_hash = None
    max_attempts = 5
    max_resends = 3
    last_sent_at = LazyFunction(timezone.now)
    expires_at = LazyFunction(lambda: timezone.now() + timedelta(minutes=5))


class AuthSessionFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = AuthSession

    id = LazyFunction(uuid.uuid4)
    user = SubFactory(UserFactory)
    current_jti = Sequence(lambda n: f"jti-{n}-{'0' * 32}")
    ip_address = "127.0.0.1"
    expires_at = LazyFunction(lambda: timezone.now() + timedelta(days=14))


class TwoFactorDeviceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = TwoFactorDevice

    user = SubFactory(UserFactory)
    method = "totp"
    secret_encrypted = "fake-encrypted-secret"  # noqa: S105 -- placeholder, never a real ciphertext
    confirmed_at = LazyFunction(timezone.now)


class RecoveryCodeFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = RecoveryCode

    user = SubFactory(UserFactory)
    code_hash = _FAKE_HASH


class VerifiedContactFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = VerifiedContact

    user = SubFactory(UserFactory)
    field = "email"
    value = Sequence(lambda n: f"verified{n}@example.com")


class LoginAttemptFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LoginAttempt

    user = SubFactory(UserFactory)
    identifier = Sequence(lambda n: f"user{n}")
    method = "password"
    ip_address = "127.0.0.1"
    success = True


class TrustedDeviceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = TrustedDevice

    user = SubFactory(UserFactory)
    token_hash = _FAKE_HASH
    expires_at = LazyFunction(lambda: timezone.now() + timedelta(days=30))

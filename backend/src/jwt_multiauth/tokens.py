"""Pure PyJWT wrapper — claim construction and verification. No database access.

Phase 3 implements ``issue(claims, *, typ, ttl_seconds) -> str`` and
``decode(token, *, expected_typ) -> dict``, plus one clearly-named exception per failure mode
(expired, bad signature, wrong ``typ``) — per ``docs/CONTRACT.md`` §0: this app owns token
issuance/verification directly via ``pyjwt``, rather than depending on
``djangorestframework-simplejwt``; ``AuthSession`` (this app's own model, Phase 2) supersedes
that library's ``token_blacklist`` app.

Signing key comes from ``jwt_multiauth.keys.get_signing_key()`` — never read from
``settings.SECRET_KEY`` directly in this module. Verifying key comes from
``jwt_multiauth.keys.get_verifying_key()`` — the two differ only when a host runs ``RS256``.
Algorithm comes from ``conf.get_setting("TOKENS")["ALGORITHM"]`` (default ``"HS256"``;
``"RS256"``-ready via a host setting ``JWT_MULTIAUTH_SIGNING_KEY``/``JWT_MULTIAUTH_VERIFYING_KEY``
pair).
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any

import jwt as pyjwt
from django.utils import timezone

from jwt_multiauth import conf, keys

#: ``typ`` claim values — a token issued for one purpose is rejected outright if presented where
#: another is expected, even with a perfectly valid signature (docs/CONTRACT.md §0).
TYP_ACCESS = "access"
TYP_REFRESH = "refresh"
TYP_PENDING_2FA = "pending_2fa"

_REQUIRED_CLAIMS = ["exp", "nbf", "iat", "jti", "typ"]


class TokenError(Exception):
    """Base class for every failure mode :func:`decode` can raise. Never raised directly —
    always one of the subclasses below, so ``services.py`` maps each to the right error detail
    without re-parsing an exception message.
    """


class TokenExpired(TokenError):
    """The token's ``exp`` claim is in the past."""


class TokenSignatureInvalid(TokenError):
    """The token's signature does not verify against :func:`jwt_multiauth.keys.get_verifying_key`
    — a tampered or forged token.
    """


class TokenMalformed(TokenError):
    """The token is not well-formed JWS, or is missing a required claim (``exp``/``nbf``/``iat``/
    ``jti``/``typ``) entirely — anything PyJWT itself rejects that isn't specifically an expiry or
    a signature failure.
    """


class TokenTypeMismatch(TokenError):
    """The token verified (signature and timestamps both valid) but its ``typ`` claim is not the
    one the caller expected — an access token presented where a refresh token belongs, etc.
    """


def generate_jti() -> str:
    """A fresh, unguessable token identifier. ``secrets``, never ``random`` (this repo's
    ``CLAUDE.md`` rule 4). 43 characters — comfortably inside ``AuthSession.current_jti``'s
    ``max_length=64``.
    """
    return secrets.token_urlsafe(32)


def issue(claims: dict[str, Any], *, typ: str, ttl_seconds: int) -> str:
    """Encode ``claims`` as a signed JWT. Sets ``iat``/``nbf``/``exp`` from the current time and
    ``ttl_seconds``, ``typ`` itself as a claim, and a fresh :func:`generate_jti` unless the caller
    already supplied one in ``claims`` (``TokenService`` does this for a refresh token, whose
    ``jti`` must equal the owning ``AuthSession.current_jti`` rather than a new random value —
    that value still originates from :func:`generate_jti` at the call site).

    Algorithm and signing key are read from ``conf``/``keys`` on every call — never hardcoded —
    so overriding ``TOKENS["ALGORITHM"]`` is never a lie.
    """
    now = timezone.now()
    payload = {
        **claims,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "typ": typ,
    }
    payload.setdefault("jti", generate_jti())

    algorithm = conf.get_setting("TOKENS")["ALGORITHM"]
    return pyjwt.encode(payload, keys.get_signing_key(), algorithm=algorithm)


def decode(token: str, *, expected_typ: str) -> dict[str, Any]:
    """Verify signature, ``exp``/``nbf``, and ``typ`` — in that order, since a token that doesn't
    even verify has no trustworthy ``typ`` claim to compare. Raises exactly one of this module's
    exceptions on any failure; never lets a raw ``jwt.exceptions.PyJWTError`` escape.
    """
    algorithm = conf.get_setting("TOKENS")["ALGORITHM"]
    try:
        claims = pyjwt.decode(
            token,
            keys.get_verifying_key(),
            algorithms=[algorithm],
            options={"require": _REQUIRED_CLAIMS},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenExpired(str(exc)) from exc
    except pyjwt.InvalidSignatureError as exc:
        raise TokenSignatureInvalid(str(exc)) from exc
    except pyjwt.InvalidTokenError as exc:
        # Catches DecodeError (malformed JWS), MissingRequiredClaimError (a required claim is
        # absent entirely), and every other InvalidTokenError subclass not named above.
        raise TokenMalformed(str(exc)) from exc

    if claims["typ"] != expected_typ:
        raise TokenTypeMismatch(f"expected typ={expected_typ!r}, got typ={claims['typ']!r}")

    return claims

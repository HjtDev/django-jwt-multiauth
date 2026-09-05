"""Pure PyJWT wrapper — claim construction and verification. No database access.

Phase 3 implements ``issue(claims, *, typ, ttl_seconds) -> str`` and
``decode(token, *, expected_typ) -> dict``, plus one clearly-named exception per failure mode
(expired, bad signature, wrong ``typ``) — per ``docs/CONTRACT.md`` §0: this app owns token
issuance/verification directly via ``pyjwt``, rather than depending on
``djangorestframework-simplejwt``; ``AuthSession`` (this app's own model, Phase 2) supersedes
that library's ``token_blacklist`` app.

Signing key comes from ``jwt_multiauth.keys.get_signing_key()`` — never read from
``settings.SECRET_KEY`` directly in this module. Algorithm comes from
``conf.get_setting("TOKENS")["ALGORITHM"]`` (default ``"HS256"``; ``"RS256"``-ready via a host
setting ``JWT_MULTIAUTH_SIGNING_KEY`` to a private key).
"""

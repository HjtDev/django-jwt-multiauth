"""Settings access layer for the ``JWT_MULTIAUTH`` settings dict, and the OTP setting resolver.

Every OTP-touching file calls :func:`get_otp_setting`, never a raw
``settings.JWT_MULTIAUTH["OTP"][...]`` dict walk. Every other setting goes through
:func:`get_setting`, the same one-place-with-defaults pattern ``APP-DESIGN.md`` §3.5 mandates for
every app in this ecosystem (see ``appkit.conf``/``dynamic_user.conf`` for the same shape).

``docs/CONTRACT.md`` §6 is the frozen source for every key and default below. Sub-dict names are
frozen (``CLAUDE.md``'s semver-trigger list): ``TOKENS``, ``REFRESH_COOKIE``, ``OTP``,
``TWO_FACTOR``, ``LOCKOUT``, ``PASSWORD``, ``USER_FIELDS``. Plus top-level
``ALLOWED_AUTH_METHODS``, ``ADMIN_REQUIRES_SUPERUSER``, ``LOGIN_ATTEMPT_RETENTION_DAYS``.

**Nested-dict merge, not override-and-lose-the-rest.** A host overriding one key inside e.g.
``TOKENS`` must not silently blank every other key in that sub-dict — :func:`get_setting` merges
a host's override dict onto :data:`DEFAULTS`' own dict value, recursively, so
``JWT_MULTIAUTH = {"TOKENS": {"ACCESS_TTL_SECONDS": 60}}`` changes only that one key and leaves
``REFRESH_TTL_SECONDS``/``REMEMBER_ME_TTL_SECONDS``/``ALGORITHM`` at their documented defaults.
This applies at every nesting depth, including ``TWO_FACTOR["TRUSTED_DEVICE"]``.

**The OTP sub-dict's override shape** — not literal anywhere in ``docs/CONTRACT.md`` §2 itself,
chosen here and recorded in ``docs/CONTRACT.md`` §11 the moment it's chosen (this file is the
frozen implementation of that choice): ``OTP["DEFAULTS"]`` (the global fallback, every key
required), ``OTP["CHANNELS"]`` (per-channel overrides, e.g. ``{"email": {"LENGTH": 8}}``), and
``OTP["PURPOSES"]`` (per-purpose overrides, e.g. ``{"password_reset": {"TTL_SECONDS": 900}}``) —
implementing §2's frozen resolution chain "purpose-override -> channel-override ->
``OTP["DEFAULTS"]``" as two flat sibling maps next to ``DEFAULTS``.

**The hash algorithm itself (HMAC-SHA256) is NOT configurable** — a deliberate non-setting, no
``HASH_ALGORITHM`` key exists or will be added "for flexibility" (``docs/CONTRACT.md`` §2).
"""

from __future__ import annotations

from typing import Any, Final

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

DEFAULTS: Final[dict[str, Any]] = {
    "ALLOWED_AUTH_METHODS": ["password"],
    "ADMIN_REQUIRES_SUPERUSER": False,
    "LOGIN_ATTEMPT_RETENTION_DAYS": 90,
    "TOKENS": {
        "ACCESS_TTL_SECONDS": 900,
        "REFRESH_TTL_SECONDS": 1_209_600,
        "REMEMBER_ME_TTL_SECONDS": 2_592_000,
        "ALGORITHM": "HS256",
    },
    "REFRESH_COOKIE": {
        "TRANSPORT": "cookie",
        "NAME": "jwt_multiauth_refresh",
        "SAMESITE": "Lax",
        "SECURE": True,
    },
    "OTP": {
        # Every key here is required — get_otp_setting() raises ImproperlyConfigured for a key
        # that isn't in this dict at all, never a silent None (docs/CONTRACT.md §2, rule 3: fail
        # closed). Baseline is 6-digit numeric / 5-minute TTL, per the guide's own worked
        # example of an SMS OTP; a host wanting an 8-char alphanumeric / 10-minute email OTP
        # sets that under OTP["CHANNELS"]["email"] instead of changing the shared default.
        "DEFAULTS": {
            "LENGTH": 6,
            "ALPHABET": "numeric",
            "EXCLUDE_AMBIGUOUS": False,
            "CASE_SENSITIVE": False,
            "TTL_SECONDS": 300,
            "MAX_ATTEMPTS": 5,
            "RESEND_COOLDOWN_SECONDS": 60,
            "MAX_RESENDS": 3,
            "SINGLE_ACTIVE_CHALLENGE": True,
            "EMIT_LINK_TOKEN": False,
        },
        "CHANNELS": {},
        "PURPOSES": {},
    },
    "TWO_FACTOR": {
        "POLICY": "off",
        "ALLOWED_METHODS": ["totp"],
        "REQUIRE_DIFFERENT_CHANNEL": True,
        "PENDING_TOKEN_TTL_SECONDS": 300,
        "RECOVERY_CODE_COUNT": 10,
        "TOTP_DRIFT_WINDOW": 1,
        "TRUSTED_DEVICE": {
            "ENABLED": False,
            "TTL_SECONDS": 2_592_000,
            "COOKIE_NAME": "jwt_multiauth_td",
        },
    },
    "LOCKOUT": {
        "MAX_ATTEMPTS": 5,
        "WINDOW_SECONDS": 900,
        "LOCK_DURATION_SECONDS": 900,
        "LOCK_SCOPE": "identifier_and_ip",
    },
    "PASSWORD": {
        "RESET_CHANNEL_PREFERENCE": ["email", "phone"],
        "REQUIRE_OLD_PASSWORD_ON_CHANGE": True,
        "REVOKE_SESSIONS_ON_CHANGE": True,
    },
    "USER_FIELDS": {
        "EMAIL_FIELD": None,
        "PHONE_FIELD": None,
        "IDENTIFIER_FIELDS": ["username", "email"],
        # Opt-in, per-method, empty by default: zero behavior change for every host that never
        # sets it (docs/CONTRACT.md §11 item 19). Drawn from "phone_otp"/"email_otp" only, never
        # "password" — an unresolved identifier on a listed method is get_or_create()d into a
        # real account (services.UserProvisioningService) instead of decoyed.
        "AUTO_PROVISION_METHODS": [],
        # Dotted path to a host callable (identifier: str, field: str) -> user that fully owns
        # creation for an AUTO_PROVISION_METHODS method. Unset uses the built-in default in
        # services.UserProvisioningService.get_or_create (docs/CONTRACT.md §11 item 19).
        "PROVISION_CALLBACK": None,
    },
}


def _deep_merge(default: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge ``override`` onto ``default``, recursively, for any key that is a dict on both
    sides — a host overriding one nested key never blanks its siblings. Not part of this
    module's public surface; called only from :func:`get_setting`.
    """
    merged = dict(default)
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def get_setting(key: str) -> Any:
    """Read a ``JWT_MULTIAUTH`` setting, falling back to this app's documented default.

    For a key whose default value is a ``dict`` (``TOKENS``, ``REFRESH_COOKIE``, ``OTP``,
    ``TWO_FACTOR``, ``LOCKOUT``, ``PASSWORD``, ``USER_FIELDS``), a host's override is merged
    recursively onto :data:`DEFAULTS`' own value — see this module's docstring.

    Raises:
        KeyError: only for a ``key`` that isn't in :data:`DEFAULTS` at all — a programming error
            inside this app itself, never a host-facing failure mode.
    """
    if key not in DEFAULTS:
        raise KeyError(f"jwt_multiauth.conf.get_setting() was given unknown key {key!r}.")

    configured: dict[str, Any] = getattr(settings, "JWT_MULTIAUTH", {})
    default = DEFAULTS[key]
    if key not in configured:
        return default

    override = configured[key]
    if isinstance(default, dict) and isinstance(override, dict):
        return _deep_merge(default, override)
    return override


def get_otp_setting(key: str, *, channel: str, purpose: str | None = None) -> Any:
    """Resolve an ``OTP`` setting: purpose-override -> channel-override ->
    ``OTP["DEFAULTS"][key]``.

    Args:
        key: one of ``OTP["DEFAULTS"]``'s keys — ``LENGTH``, ``ALPHABET``, ``EXCLUDE_AMBIGUOUS``,
            ``CASE_SENSITIVE``, ``TTL_SECONDS``, ``MAX_ATTEMPTS``, ``RESEND_COOLDOWN_SECONDS``,
            ``MAX_RESENDS``, ``SINGLE_ACTIVE_CHALLENGE``, or ``EMIT_LINK_TOKEN``.
        channel: e.g. ``"email"``/``"phone"`` — looked up in ``OTP["CHANNELS"]``.
        purpose: e.g. ``"login"``/``"password_reset"`` — looked up in ``OTP["PURPOSES"]``, ahead
            of the channel override, when given.

    Raises:
        ImproperlyConfigured: ``key`` is not one of ``OTP["DEFAULTS"]``'s keys — never a silent
            ``None``, since a silently-``None`` TTL or ``MAX_ATTEMPTS`` is exactly the kind of
            soft failure this repo's fail-closed rail exists to prevent.
    """
    otp_settings = get_setting("OTP")
    defaults = otp_settings["DEFAULTS"]
    if key not in defaults:
        raise ImproperlyConfigured(
            f'jwt_multiauth.conf.get_otp_setting() was given unknown key "{key}" — valid keys '
            f"are: {', '.join(sorted(defaults))}."
        )

    if purpose is not None:
        purpose_override = otp_settings.get("PURPOSES", {}).get(purpose, {})
        if key in purpose_override:
            return purpose_override[key]

    channel_override = otp_settings.get("CHANNELS", {}).get(channel, {})
    if key in channel_override:
        return channel_override[key]

    return defaults[key]

"""Django system checks registered by :class:`jwt_multiauth.apps.JwtMultiauthConfig.ready`.

Implements this repo's ``CLAUDE.md`` rule 2 / ``docs/CONTRACT.md`` §0 item 2: the resolved user
model, and the host's ``.env``, are validated **per enabled method**, never assumed — a method a
host never turns on imposes no requirement at all, and a missing requirement is a named
``manage.py check``-time error, never a runtime ``500`` the first time someone tries to log in
with it.

"Active" (the set every check below validates against) is ``ALLOWED_AUTH_METHODS`` unioned with
``TWO_FACTOR["ALLOWED_METHODS"]`` **only while** ``TWO_FACTOR["POLICY"] != "off"`` —
``docs/CONTRACT.md`` §6 states plainly that ``POLICY == "off"`` means "no 2FA is ever offered or
required, regardless of ``ALLOWED_METHODS``/enrollment", so a method sitting in that list while
policy is off imposes nothing (mirrors §6's own encryption-key interaction, which is gated the
same way). ``ALLOWED_AUTH_METHODS`` itself is never gated by ``POLICY`` — it governs login, not
second-factor enrollment.

At the default configuration (``ALLOWED_AUTH_METHODS = ["password"]``,
``TWO_FACTOR["POLICY"] = "off"``), the active set is ``{"password"}`` — a method with no field or
key requirement at all — so every check below returns an empty list against a fresh, zero-config
Django project.

Eight check IDs:

    jwt_multiauth.E001 (Error)   — an active method's USER_FIELDS entry is unset (None)
                                    -> check_user_field_requirements
    jwt_multiauth.E002 (Error)   — the named field doesn't exist on the resolved user model
                                    -> check_user_field_requirements
    jwt_multiauth.E003 (Error)   — the named field exists but isn't unique
                                    -> check_user_field_requirements
    jwt_multiauth.E004 (Error)   — "totp" is active but JWT_MULTIAUTH_ENCRYPTION_KEY is unset
                                    -> check_totp_requirements
    jwt_multiauth.E005 (Error)   — "totp" is active but the `totp` extra isn't importable
                                    -> check_totp_requirements
    jwt_multiauth.E006 (Error)   — an unrecognised string in ALLOWED_AUTH_METHODS or
                                    TWO_FACTOR["ALLOWED_METHODS"] (both closed sets,
                                    docs/CONTRACT.md §12)
                                    -> check_allowed_methods_closed_set
    jwt_multiauth.W001 (Warning) — JWT_MULTIAUTH contains a key not present in conf.DEFAULTS
                                    -> check_unknown_settings_keys

Every function below is defensive by construction, mirroring ``appkit.checks``' own stated rule:
a system check that raises breaks ``manage.py`` entirely, including the commands someone would
use to fix the thing it's complaining about — every one of these treats an unexpected failure
while inspecting the resolved model/settings as "nothing to report", never a crash.
"""

from __future__ import annotations

import logging
from typing import Any, Final

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.checks import CheckMessage, Error, Warning
from django.core.exceptions import FieldDoesNotExist

from jwt_multiauth import conf

logger = logging.getLogger(__name__)

#: The closed set of accepted ALLOWED_AUTH_METHODS strings (docs/CONTRACT.md §12 — adding to or
#: removing from this set is a MAJOR version bump).
ALLOWED_LOGIN_METHODS: Final[frozenset[str]] = frozenset({"password", "phone_otp", "email_otp"})

#: The closed set of accepted TWO_FACTOR["ALLOWED_METHODS"] strings (docs/CONTRACT.md §12, same
#: rule as above).
ALLOWED_TWO_FACTOR_METHODS: Final[frozenset[str]] = frozenset(
    {"totp", "email_otp", "phone_otp", "recovery_code"}
)


def _active_methods() -> set[str]:
    """``ALLOWED_AUTH_METHODS`` unioned with ``TWO_FACTOR["ALLOWED_METHODS"]`` — the latter only
    while ``TWO_FACTOR["POLICY"] != "off"``. See this module's docstring for why. Not part of
    this module's public surface.
    """
    login_methods = set(conf.get_setting("ALLOWED_AUTH_METHODS"))
    two_factor = conf.get_setting("TWO_FACTOR")
    if two_factor["POLICY"] == "off":
        return login_methods
    return login_methods | set(two_factor["ALLOWED_METHODS"])


def check_user_field_requirements(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """jwt_multiauth.E001 / E002 / E003 — validates ``USER_FIELDS["PHONE_FIELD"]``/
    ``["EMAIL_FIELD"]`` against the resolved user model, but only for a method that is actually
    active (see this module's docstring).

    A non-unique identifier field is rejected (E003), not merely warned about: an ambiguous
    identifier is exactly what this repo's fail-closed rule (rule 3) says must be rejected, not
    silently tolerated. This is expected to fire for a host that enables ``"email_otp"`` against
    stock ``django.contrib.auth.User`` — whose ``email`` field is not unique by default.
    """
    try:
        active = _active_methods()
        errors: list[CheckMessage] = []
        if "phone_otp" in active:
            errors.extend(_check_identifier_field("PHONE_FIELD", "phone_otp"))
        if "email_otp" in active:
            errors.extend(_check_identifier_field("EMAIL_FIELD", "email_otp"))
        return errors
    except Exception:
        logger.debug(
            "jwt_multiauth.checks.check_user_field_requirements: failed to inspect the "
            "resolved user model",
            exc_info=True,
        )
        return []


def _check_identifier_field(setting_key: str, method_name: str) -> list[CheckMessage]:
    """Shared implementation behind :func:`check_user_field_requirements` for one
    ``USER_FIELDS`` entry. Not part of this module's public surface.
    """
    user_fields = conf.get_setting("USER_FIELDS")
    field_name = user_fields[setting_key]

    if not field_name:
        return [
            Error(
                f'"{method_name}" is enabled but '
                f'JWT_MULTIAUTH["USER_FIELDS"]["{setting_key}"] is not set.',
                hint=(
                    f'Set JWT_MULTIAUTH["USER_FIELDS"]["{setting_key}"] to the name of a '
                    f'unique, nullable field on your user model, or remove "{method_name}" '
                    "from the enabled method list — docs/CONTRACT.md §6."
                ),
                id="jwt_multiauth.E001",
            )
        ]

    model = get_user_model()
    try:
        field = model._meta.get_field(field_name)
    except FieldDoesNotExist:
        return [
            Error(
                f'JWT_MULTIAUTH["USER_FIELDS"]["{setting_key}"] names "{field_name}", which '
                f"does not exist on {model._meta.label}.",
                hint=(
                    f'Point JWT_MULTIAUTH["USER_FIELDS"]["{setting_key}"] at a real field on '
                    f"{model._meta.label} — docs/CONTRACT.md §6."
                ),
                id="jwt_multiauth.E002",
            )
        ]

    if not getattr(field, "unique", False):
        return [
            Error(
                f'JWT_MULTIAUTH["USER_FIELDS"]["{setting_key}"] names "{field_name}" on '
                f"{model._meta.label}, which is not unique.",
                hint=(
                    "A non-unique field is an ambiguous identifier — this app fails closed on "
                    f"an ambiguous identifier rather than guessing which row it means. Add "
                    f'unique=True to "{field_name}" (with a migration), or point '
                    f'JWT_MULTIAUTH["USER_FIELDS"]["{setting_key}"] at a field that already is '
                    "unique — docs/CONTRACT.md §6, this repo's CLAUDE.md rule 3."
                ),
                id="jwt_multiauth.E003",
            )
        ]

    return []


def check_totp_requirements(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """jwt_multiauth.E004 / E005 — when ``"totp"`` is active (see this module's docstring),
    verifies ``JWT_MULTIAUTH_ENCRYPTION_KEY`` is set and the ``totp`` extra is importable.
    """
    try:
        if "totp" not in _active_methods():
            return []

        errors: list[CheckMessage] = []
        if not getattr(settings, "JWT_MULTIAUTH_ENCRYPTION_KEY", None):
            errors.append(
                Error(
                    '"totp" is enabled but JWT_MULTIAUTH_ENCRYPTION_KEY is not set.',
                    hint=(
                        "Set JWT_MULTIAUTH_ENCRYPTION_KEY in your environment — generate one "
                        "with appkit.crypto.generate_key(). This key is never derived from "
                        "SECRET_KEY, by design — docs/CONTRACT.md §6."
                    ),
                    id="jwt_multiauth.E004",
                )
            )

        try:
            import pyotp  # noqa: F401
        except ImportError:
            errors.append(
                Error(
                    '"totp" is enabled but the `totp` extra is not installed.',
                    hint='Install with: uv add "django-jwt-multiauth[totp]".',
                    id="jwt_multiauth.E005",
                )
            )

        return errors
    except Exception:
        logger.debug(
            "jwt_multiauth.checks.check_totp_requirements: failed to inspect totp requirements",
            exc_info=True,
        )
        return []


def check_allowed_methods_closed_set(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """jwt_multiauth.E006 — Error if ``ALLOWED_AUTH_METHODS`` or
    ``TWO_FACTOR["ALLOWED_METHODS"]`` contains a value outside its closed set
    (``docs/CONTRACT.md`` §12 — both sets are frozen; adding or removing a member is a MAJOR
    version bump, never a silent typo-tolerant default).
    """
    try:
        errors: list[CheckMessage] = []

        login_methods = set(conf.get_setting("ALLOWED_AUTH_METHODS"))
        unknown_login = sorted(login_methods - ALLOWED_LOGIN_METHODS)
        if unknown_login:
            errors.append(
                Error(
                    f'JWT_MULTIAUTH["ALLOWED_AUTH_METHODS"] contains unrecognised value(s): '
                    f"{', '.join(unknown_login)}.",
                    hint=f"Valid values are: {', '.join(sorted(ALLOWED_LOGIN_METHODS))}.",
                    id="jwt_multiauth.E006",
                )
            )

        two_factor_methods = set(conf.get_setting("TWO_FACTOR")["ALLOWED_METHODS"])
        unknown_two_factor = sorted(two_factor_methods - ALLOWED_TWO_FACTOR_METHODS)
        if unknown_two_factor:
            errors.append(
                Error(
                    f'JWT_MULTIAUTH["TWO_FACTOR"]["ALLOWED_METHODS"] contains unrecognised '
                    f"value(s): {', '.join(unknown_two_factor)}.",
                    hint=f"Valid values are: {', '.join(sorted(ALLOWED_TWO_FACTOR_METHODS))}.",
                    id="jwt_multiauth.E006",
                )
            )

        return errors
    except Exception:
        logger.debug(
            "jwt_multiauth.checks.check_allowed_methods_closed_set: failed to inspect "
            "configured methods",
            exc_info=True,
        )
        return []


def check_unknown_settings_keys(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    """jwt_multiauth.W001 — Warning if the host's ``JWT_MULTIAUTH`` dict contains a top-level
    key not present in :data:`jwt_multiauth.conf.DEFAULTS`.

    A typo (``JWT_MULTIAUTH = {"ALLOWED_AUTH_METHOD": [...]}``) would otherwise silently use the
    *default* ``ALLOWED_AUTH_METHODS`` forever, with the typo'd key simply ignored — mirrors
    ``appkit.checks.check_unknown_settings_keys`` exactly.
    """
    try:
        configured = getattr(settings, "JWT_MULTIAUTH", None) or {}
        unknown = sorted(set(configured) - set(conf.DEFAULTS))
        if not unknown:
            return []
        return [
            Warning(
                f"JWT_MULTIAUTH contains unrecognised key(s): {', '.join(unknown)}.",
                hint=(
                    f"Known top-level JWT_MULTIAUTH keys: {', '.join(sorted(conf.DEFAULTS))} "
                    "(docs/CONTRACT.md §6). A typo'd key is silently ignored — its value is "
                    "never read."
                ),
                id="jwt_multiauth.W001",
            )
        ]
    except Exception:
        logger.debug(
            "jwt_multiauth.checks.check_unknown_settings_keys: failed to inspect JWT_MULTIAUTH",
            exc_info=True,
        )
        return []

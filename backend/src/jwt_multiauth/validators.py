"""Reserved. Neither ``docs/CONTRACT.md`` nor this app's own build guide documents a role for
this module beyond listing it among Phase 1's stub files — password validation goes through
Django's own ``AUTH_PASSWORD_VALIDATORS`` setting, not a validator this app defines.

Left as an empty, present module rather than omitted entirely, in case a later phase needs an
identifier-format or OTP-input validator that doesn't belong in ``serializers.py`` directly. If
no such need materializes by v1.0.0, this file stays a documented no-op rather than being
removed — removing a module a host might already reference (even just via
``ruff``'s/``mypy``'s awareness of it) is a needless surface change this app avoids making
without a reason.
"""

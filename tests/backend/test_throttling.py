"""Proves every public scope constant in ``jwt_multiauth.throttling`` has a matching
``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]`` entry (mirrors what ``appkit.checks.
check_throttle_scopes``/``appkit.W004`` would warn about at ``manage.py check`` time for a real
view, but proven here directly against the constants module so a missing rate is caught even
before any view exists), and that no two constants collide on the same scope string.
"""

from __future__ import annotations

from django.conf import settings

from jwt_multiauth import throttling


def _public_scope_constants() -> dict[str, str]:
    return {
        name: value
        for name, value in vars(throttling).items()
        if name.isupper() and isinstance(value, str)
    }


def test_every_throttle_scope_has_a_matching_rate() -> None:
    scopes = _public_scope_constants()
    known_rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
    missing = [name for name, scope in scopes.items() if scope not in known_rates]
    assert missing == []


def test_no_duplicate_scope_strings() -> None:
    scopes = _public_scope_constants()
    values = list(scopes.values())
    assert len(values) == len(set(values))


def test_every_scope_string_is_namespaced_under_jwt_multiauth() -> None:
    scopes = _public_scope_constants()
    assert all(scope.startswith("jwt_multiauth") for scope in scopes.values())

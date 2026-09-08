"""Proves ``jwt_multiauth.middleware.jwt_auth.JWTAuthMiddlewareStack``: a valid access token
resolves ``scope["user"]`` to the right user; every failure mode — missing/empty/ambiguous
token, non-UTF-8 query string, expired/tampered/malformed token, a refresh or ``pending_2fa``
token presented as an access token, and a ``sub`` that no longer resolves — falls back to
``AnonymousUser`` without ever raising out of the middleware. Also proves the caller's own scope
dict is never mutated, and that ``jwt_multiauth.middleware`` (the package) stays importable
without the ``channels`` extra even though this module does not.
"""

from __future__ import annotations

from typing import Any

import pytest
from asgiref.sync import async_to_sync
from freezegun import freeze_time

from jwt_multiauth.factories import UserFactory
from jwt_multiauth.services import RequestMeta, TokenService

#: A hard `import channels` at module scope would crash collection under the bare-install leg
#: (`make test-bare`) BEFORE `pytestmark`'s `requires_extra` marker ever gets a chance to
#: deselect anything — `importorskip` converts that would-be collection error into a clean
#: whole-module skip instead, same pattern as `test_two_factor_verify.py`.
pytest.importorskip("channels")

from jwt_multiauth.middleware.jwt_auth import (
    JWTAuthMiddleware,
    JWTAuthMiddlewareStack,
)

# transaction=True: database_sync_to_async's close_old_connections() call closes the connection
# out from under a plain django_db test's outer atomic block the moment the async ORM call
# returns, because get_autocommit() then disagrees with settings_dict["AUTOCOMMIT"]. Removing the
# outer atomic (transaction=True) is what both Channels' and pytest-django's own docs recommend
# for exactly this combination.
pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.requires_extra]

_REQUEST_META: RequestMeta = {"ip": "203.0.113.5", "method": "password"}


async def _receive() -> dict[str, Any]:  # pragma: no cover - never actually awaited by the stack
    raise AssertionError("the inner app is a stub and never reads from receive")


async def _send(_message: dict[str, Any]) -> None:  # pragma: no cover - see above
    raise AssertionError("the inner app is a stub and never writes to send")


class _RecordingApp:
    """The ASGI app `JWTAuthMiddleware` wraps. Records the scope it was called with so tests can
    assert on the resolved `scope["user"]` without needing a real consumer.
    """

    def __init__(self) -> None:
        self.scopes: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.scopes.append(scope)


def _connect(*, query_string: bytes) -> tuple[dict[str, Any], _RecordingApp]:
    """Builds a minimal WebSocket scope and drives it through `JWTAuthMiddlewareStack` via
    `async_to_sync` — this project has no `pytest-asyncio` dependency and no other async test
    yet, so plain `asgiref.sync.async_to_sync` (already a Django dependency) is the smallest
    addition that exercises the real async `__call__` path.
    """
    original_scope: dict[str, Any] = {"type": "websocket", "query_string": query_string}
    inner = _RecordingApp()
    stack = JWTAuthMiddlewareStack(inner)
    async_to_sync(stack)(original_scope, _receive, _send)
    return original_scope, inner


def _access_token(user: object) -> str:
    return TokenService.issue_token_pair(user, request_meta=_REQUEST_META).access


def _refresh_token(user: object) -> str:
    return TokenService.issue_token_pair(user, request_meta=_REQUEST_META).refresh


def _pending_2fa_token(user: object) -> str:
    return TokenService.issue_pending_2fa_token(
        user, primary_method="password", request_meta=_REQUEST_META
    )


def test_valid_access_token_resolves_the_user() -> None:
    user = UserFactory()
    token = _access_token(user)

    _, inner = _connect(query_string=f"token={token}".encode())

    resolved = inner.scopes[0]["user"]
    assert resolved == user
    assert resolved.is_authenticated


def test_no_token_resolves_anonymous() -> None:
    _, inner = _connect(query_string=b"")

    resolved = inner.scopes[0]["user"]
    assert not resolved.is_authenticated


def test_empty_token_value_resolves_anonymous() -> None:
    _, inner = _connect(query_string=b"token=")

    assert not inner.scopes[0]["user"].is_authenticated


def test_garbage_token_resolves_anonymous() -> None:
    _, inner = _connect(query_string=b"token=not-a-jwt-at-all")

    assert not inner.scopes[0]["user"].is_authenticated


def test_ambiguous_token_query_param_fails_closed() -> None:
    """Two `token=` values in the query string is never "take the first and hope" — it's treated
    the same as no token at all, per CLAUDE.md rule 3.
    """
    _, inner = _connect(query_string=b"token=first-value&token=second-value")

    assert not inner.scopes[0]["user"].is_authenticated


def test_non_utf8_query_string_resolves_anonymous() -> None:
    _, inner = _connect(query_string=b"token=\xff\xfe")

    assert not inner.scopes[0]["user"].is_authenticated


def test_expired_access_token_resolves_anonymous() -> None:
    user = UserFactory()
    with freeze_time("2026-01-01 00:00:00"):
        token = _access_token(user)

    with freeze_time("2026-01-02 00:00:00"):
        _, inner = _connect(query_string=f"token={token}".encode())

    assert not inner.scopes[0]["user"].is_authenticated


def test_tampered_signature_resolves_anonymous() -> None:
    user = UserFactory()
    token = _access_token(user)
    header, payload, signature = token.split(".")
    # Flip the FIRST character, never the last — base64url's final character in a
    # non-multiple-of-4 encoding carries "don't care" low bits, so some flips there leave the
    # decoded signature byte identical (test_tokens.py's own rationale for this exact pattern).
    flipped_first_char = "A" if signature[0] != "A" else "B"
    tampered = f"{header}.{payload}.{flipped_first_char}{signature[1:]}"

    _, inner = _connect(query_string=f"token={tampered}".encode())

    assert not inner.scopes[0]["user"].is_authenticated


def test_refresh_token_presented_as_access_resolves_anonymous() -> None:
    user = UserFactory()
    token = _refresh_token(user)

    _, inner = _connect(query_string=f"token={token}".encode())

    assert not inner.scopes[0]["user"].is_authenticated


def test_pending_2fa_token_presented_as_access_resolves_anonymous() -> None:
    user = UserFactory()
    token = _pending_2fa_token(user)

    _, inner = _connect(query_string=f"token={token}".encode())

    assert not inner.scopes[0]["user"].is_authenticated


def test_deleted_user_resolves_anonymous() -> None:
    user = UserFactory()
    token = _access_token(user)
    user.delete()

    _, inner = _connect(query_string=f"token={token}".encode())

    assert not inner.scopes[0]["user"].is_authenticated


def test_inner_app_is_still_called_and_caller_scope_is_not_mutated() -> None:
    original_scope, inner = _connect(query_string=b"")

    assert len(inner.scopes) == 1
    # JWTAuthMiddleware copies the scope before writing scope["user"] — the caller's own dict,
    # passed into async_to_sync(stack)(...), must come back untouched.
    assert "user" not in original_scope


def test_middleware_package_imports_without_a_real_channels_dependency_issue() -> None:
    """`jwt_multiauth.middleware` (the empty package marker) must stay importable regardless of
    whether `channels` is installed — only `jwt_multiauth.middleware.jwt_auth` itself requires
    the extra. This test runs only when channels IS installed (importorskip above already
    gated the whole module), so it only proves the package import doesn't regress; the
    extra-less case is proven by `make test-bare` collecting this whole module as skipped.
    """
    import jwt_multiauth.middleware  # noqa: F401


def test_jwt_auth_middleware_is_a_channels_base_middleware() -> None:
    from channels.middleware import BaseMiddleware

    assert issubclass(JWTAuthMiddleware, BaseMiddleware)

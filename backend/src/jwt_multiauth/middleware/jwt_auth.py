"""``JWTAuthMiddlewareStack`` — optional Channels WebSocket authentication, behind the
``channels`` extra.

Phase 9 implements ``JWTAuthMiddlewareStack(inner)``: reads a token from the WebSocket handshake
query string (``?token=...``), calls ``TokenService.verify_access_token`` (``services.py``), and
sets ``scope["user"]`` — ``AnonymousUser`` on any failure, never raising out of the middleware.
Rejects a refresh or ``pending_2fa`` token via ``tokens.py``'s own ``typ`` check, same as the DRF
authentication classes. Explicitly **not** a substitute for a consuming app's per-consumer
authorization — it only establishes ``scope["user"]``, exactly what
``channels.auth.AuthMiddlewareStack`` does for the session-cookie case.

The import guard below is the point of this docstring: a host without the ``channels`` extra
installed must get an actionable ``ImportError`` naming the fix, at the moment it tries to import
this module — never a bare, unhelpful ``ModuleNotFoundError`` raised from deep inside Channels'
own import machinery. Every other module in this package must remain importable regardless of
whether ``channels`` is installed; only importing *this* module requires it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

_INSTALL_HINT = 'Install with: uv add "django-jwt-multiauth[channels]"'

try:
    import channels  # noqa: F401
except ImportError as exc:
    raise ImportError(
        f"jwt_multiauth.middleware.jwt_auth requires the 'channels' package. {_INSTALL_HINT}"
    ) from exc

# Real channels/Django imports only reach here once the guard above has already succeeded — a
# host without the extra never pays for (or fails inside) these.
from channels.db import database_sync_to_async  # noqa: E402
from channels.middleware import BaseMiddleware  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402

# AnonymousUser is NOT a concrete user-model import (CLAUDE.md rule 1) — it's the same sentinel
# channels.auth.AuthMiddleware itself assigns on failure. The real user is still resolved via
# get_user_model() below.
from django.contrib.auth.models import AnonymousUser  # noqa: E402

from jwt_multiauth import tokens  # noqa: E402
from jwt_multiauth.services import TokenService  # noqa: E402

__all__ = ["JWTAuthMiddleware", "JWTAuthMiddlewareStack"]

_QUERY_PARAM = "token"


def _token_from_scope(scope: dict[str, Any]) -> str | None:
    """Extracts the access token from the handshake's ``?token=...`` query string. Returns
    ``None`` — never raises — on anything short of exactly one non-empty value: absent,
    empty, non-UTF-8 bytes, or more than one ``token=`` param all fail closed the same way
    (CLAUDE.md rule 3), rather than guessing which of several supplied values to trust.
    """
    raw_query: bytes = scope.get("query_string", b"")
    try:
        query_string: str = raw_query.decode("utf-8")
    except UnicodeDecodeError:
        return None

    values: list[str] = parse_qs(query_string).get(_QUERY_PARAM, [])
    if len(values) != 1 or not values[0]:
        return None
    return values[0]


@database_sync_to_async
def _resolve_user(raw_token: str) -> object:
    """Mirrors ``authentication.JWTAuthentication.authenticate``'s resolution exactly — that is
    already the reviewed HTTP-side version of this same token-to-user lookup. Deliberately has
    no ``is_active`` check, same as that class: adding one only here would make a socket and an
    HTTP request disagree about the meaning of the same access token.
    """
    try:
        # The ONLY decode path — verify_access_token is tokens.decode(expected_typ=TYP_ACCESS),
        # so a refresh or pending_2fa token is rejected by tokens.py's own typ check, never a
        # second hand-rolled one here.
        claims = TokenService.verify_access_token(raw_token)
    except tokens.TokenError:
        return AnonymousUser()

    user_model = get_user_model()
    try:
        return user_model.objects.get(pk=claims["sub"])
    except (user_model.DoesNotExist, ValueError, TypeError):
        return AnonymousUser()


class JWTAuthMiddleware(BaseMiddleware):
    """Resolves ``scope["user"]`` from a ``?token=<access-token>`` WebSocket handshake query
    param. Falls back to ``AnonymousUser`` on every failure — expired, malformed, forged, wrong
    ``typ``, unresolvable ``sub``, missing or ambiguous token — and never raises out of the
    middleware itself: an exception here would otherwise surface as an opaque 500 at the ASGI
    layer instead of a clean anonymous connection.

    This only establishes identity. It is explicitly **not** a substitute for a consuming app's
    own per-consumer authorization check — ``scope["user"]`` being set proves who is connecting,
    not that this user may open this particular socket. See ``APP-DESIGN.md`` §6's own
    ``NotificationConsumer`` example, which still checks ``scope["user"].is_authenticated``
    itself before accepting.
    """

    async def __call__(self, scope: dict[str, Any], receive: object, send: object) -> object:
        # Copy before mutating: BaseMiddleware.__call__ also copies the scope before passing it
        # further down the stack, so writing scope["user"] first would otherwise leak the
        # mutation back into the caller's own dict.
        scope = dict(scope)
        raw_token = _token_from_scope(scope)
        scope["user"] = AnonymousUser() if raw_token is None else await _resolve_user(raw_token)
        return await super().__call__(scope, receive, send)


def JWTAuthMiddlewareStack(inner: object) -> JWTAuthMiddleware:
    """Wraps ``inner`` in :class:`JWTAuthMiddleware` — named, and shaped as a callable factory,
    for symmetry with ``channels.auth.AuthMiddlewareStack``. The host mounts this explicitly in
    ``config/asgi.py``, the same way it composes any other ``websocket_urlpatterns`` stack
    (``APP-DESIGN.md`` §6) — this package ships no consumer of its own, only the middleware::

        # config/asgi.py
        from channels.routing import ProtocolTypeRouter, URLRouter
        from django.core.asgi import get_asgi_application
        from jwt_multiauth.middleware.jwt_auth import JWTAuthMiddlewareStack

        from notifications_app.routing import websocket_urlpatterns

        application = ProtocolTypeRouter({
            "http": get_asgi_application(),
            "websocket": JWTAuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
        })
    """
    return JWTAuthMiddleware(inner)

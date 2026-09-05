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

_INSTALL_HINT = 'Install with: uv add "django-jwt-multiauth[channels]"'

try:
    import channels  # noqa: F401
except ImportError as exc:
    raise ImportError(
        f"jwt_multiauth.middleware.jwt_auth requires the 'channels' package. {_INSTALL_HINT}"
    ) from exc

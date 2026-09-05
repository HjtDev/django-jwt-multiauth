"""The admin DRF API — basePath ``/api/v1/admin/auth``.

Phase 8 implements the views backing ``urls_admin.py``'s routes per ``docs/CONTRACT.md`` §5:
session list/revoke, trusted-device list/revoke, login-attempt list, per-user security summary,
account unlock, and force-disable-2FA — every one gated by ``permissions.py``'s single admin
gate, resolved once from ``JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]``, plus a
``jwt_multiauth_admin_``-prefixed throttle scope (``throttling.py``) and a complete
``@extend_schema`` tagged ``["jwt-multiauth-admin"]``.

Force-disable-2FA is ``is_superuser``-only **unconditionally**, regardless of
``ADMIN_REQUIRES_SUPERUSER`` (``docs/CONTRACT.md`` §0 — the one admin gate that setting never
loosens). No response here ever exposes a password, a code, a ``code_hash``, a ``token_hash``, or
``secret_encrypted``.
"""

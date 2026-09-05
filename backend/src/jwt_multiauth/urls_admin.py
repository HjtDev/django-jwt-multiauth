"""Admin URLconf, basePath ``/api/v1/admin/auth``, frontend basePath key
``jwt_multiauth_admin``.

``docs/CONTRACT.md`` §5's admin routes land here in Phase 8 — session list/revoke, trusted-device
list/revoke, login-attempt list, per-user security summary, account unlock, force-disable-2FA. A
host mounts this module separately from ``urls.py``, under its own namespace/permission tier —
never merged with the self-service surface.
"""

from __future__ import annotations

from django.urls import URLPattern

urlpatterns: list[URLPattern] = []

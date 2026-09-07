"""Admin URLconf, basePath ``/api/v1/admin/auth``, frontend basePath key
``jwt_multiauth_admin``.

``docs/CONTRACT.md`` §5's admin routes land here in Phase 8 — session list/revoke, trusted-device
list/revoke, login-attempt list, per-user security summary, account unlock, force-disable-2FA. A
host mounts this module separately from ``urls.py``, under its own namespace/permission tier —
never merged with the self-service surface.

No ``app_name``, flat hyphenated ``jwt-multiauth-admin-*`` names — same convention as ``urls.py``.
Patterns below carry no ``admin/`` segment of their own: ``docs/CONTRACT.md`` §5's ``/admin/...``
paths already include the basePath a host mounts this module at (``api/v1/admin/auth/``, per
``tests/backend/urls.py``), so ``"sessions/"`` here plus that basePath reproduces
``/admin/sessions/`` exactly.
"""

from __future__ import annotations

from django.urls import URLPattern, path

from jwt_multiauth.admin_views import (
    AdminForceDisableTwoFactorView,
    AdminLoginAttemptListView,
    AdminSessionListView,
    AdminSessionRevokeView,
    AdminTrustedDeviceListView,
    AdminTrustedDeviceRevokeView,
    AdminUserSecurityView,
    AdminUserUnlockView,
)

urlpatterns: list[URLPattern] = [
    path("sessions/", AdminSessionListView.as_view(), name="jwt-multiauth-admin-sessions"),
    path(
        "sessions/<uuid:pk>/",
        AdminSessionRevokeView.as_view(),
        name="jwt-multiauth-admin-sessions-revoke",
    ),
    path(
        "trusted-devices/",
        AdminTrustedDeviceListView.as_view(),
        name="jwt-multiauth-admin-trusted-devices",
    ),
    path(
        "trusted-devices/<int:pk>/",
        AdminTrustedDeviceRevokeView.as_view(),
        name="jwt-multiauth-admin-trusted-devices-revoke",
    ),
    path(
        "login-attempts/",
        AdminLoginAttemptListView.as_view(),
        name="jwt-multiauth-admin-login-attempts",
    ),
    path(
        "users/<int:pk>/security/",
        AdminUserSecurityView.as_view(),
        name="jwt-multiauth-admin-user-security",
    ),
    path(
        "users/<int:pk>/unlock/",
        AdminUserUnlockView.as_view(),
        name="jwt-multiauth-admin-user-unlock",
    ),
    path(
        "users/<int:pk>/2fa/force-disable/",
        AdminForceDisableTwoFactorView.as_view(),
        name="jwt-multiauth-admin-2fa-force-disable",
    ),
]

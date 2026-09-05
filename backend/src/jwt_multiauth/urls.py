"""Self-service URLconf, basePath ``/api/v1/auth``, frontend basePath key ``jwt_multiauth``.

``docs/CONTRACT.md`` §5's self-service routes land here across Phases 6-8 — login, password
change/reset, OTP request/verify/resend, token refresh/verify, logout(-all), 2FA verify/status/
enroll/confirm/disable/recovery-regenerate, session and trusted-device list/revoke, contact
verification. A host mounts this module under its own API namespace; ``urls_admin.py``
(admin-only) is mounted separately, under a different namespace/permission tier entirely.
"""

from __future__ import annotations

from django.urls import URLPattern

urlpatterns: list[URLPattern] = []

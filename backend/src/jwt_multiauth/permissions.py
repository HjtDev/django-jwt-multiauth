"""Self-service and admin DRF permission classes.

Phase 8 implements the admin gate: the single callable/class every ``admin_views.py`` view
imports, resolved once from ``JWT_MULTIAUTH["ADMIN_REQUIRES_SUPERUSER"]`` (``False`` behaves like
``appkit.permissions.IsAppAdmin`` — ``is_staff``; ``True`` tightens to ``is_superuser``) — never a
conditional repeated per view, per ``docs/CONTRACT.md`` §5. Plus a **separate**, always-
``is_superuser`` gate used only by force-disable-2FA, never affected by that setting
(``docs/CONTRACT.md`` §0's "Admin gating" row).

Self-service permission checks (own-session/own-trusted-device ownership) are added alongside
their views in Phase 8.
"""

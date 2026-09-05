"""Token lifecycle views: refresh, verify, logout, logout-all.

Implements the views backing ``urls.py``'s ``/token/refresh/``, ``/token/verify/``,
``/logout/``, ``/logout-all/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md`` §5.
``POST /token/refresh/`` is where refresh-token rotation and reuse detection surface at the HTTP
layer — a reused (already-rotated) refresh token revokes the whole session chain and emits
``refresh_reuse_detected``, never silently issuing a fresh pair. ``TokenService``
(``services.py``, Phase 3) does the actual rotation/verification work; this module only
translates HTTP <-> service calls.
"""

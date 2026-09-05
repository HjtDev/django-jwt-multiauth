"""Password-based self-service views: login, password change, password reset request/confirm.

Phase 6 implements the views backing ``urls.py``'s ``/login/``, ``/password/change/``,
``/password/reset/request/``, ``/password/reset/confirm/`` routes (basePath ``/api/v1/auth``),
per ``docs/CONTRACT.md`` §5. Every identifier-taking endpoint here returns the same status, body
shape, and near-identical timing for an unknown identifier and a known identifier with a wrong
credential (this repo's ``CLAUDE.md`` rule 5) — ``POST /password/reset/request/`` always returns
``200`` regardless of whether the identifier resolves to a real, active account. ``PasswordService``
(``services.py``) does the actual authentication/reset work; this module only translates
HTTP <-> service calls.
"""

"""Self-service session and trusted-device views: list/revoke own sessions, list/revoke own
trusted devices.

Phase 8 implements the views backing ``urls.py``'s ``/sessions/``, ``/sessions/{id}/``,
``/trusted-devices/``, ``/trusted-devices/{id}/`` routes (basePath ``/api/v1/auth``), per
``docs/CONTRACT.md`` §5/§11 item 2. Every queryset here is filtered to the caller's own rows at
the query level — never a raw lookup by id alone, which would let one authenticated user revoke
another's session by guessing an id. Revocation goes through ``TokenService.revoke_session``
(``services.py``), never a raw queryset ``.update()``, so the revoked-session/``session_revoked``
signal path always fires.
"""

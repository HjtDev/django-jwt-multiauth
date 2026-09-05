"""Two-factor authentication self-service views: verify, status, TOTP enroll/confirm, disable,
recovery-code regenerate.

Phase 7 implements the views backing ``urls.py``'s ``/2fa/verify/``, ``/2fa/status/``,
``/2fa/totp/enroll/``, ``/2fa/totp/confirm/``, ``/2fa/disable/``,
``/2fa/recovery-codes/regenerate/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md``
§5. ``TWO_FACTOR["REQUIRE_DIFFERENT_CHANNEL"]`` leaving a user with zero eligible methods fails
the login outright — never degrades to single-factor (this repo's CLAUDE.md rule 3). No endpoint
here (or anywhere in this app) returns an access token before a required second factor completes,
under any settings combination. ``TwoFactorService`` (``services.py``, Phase 5) does the actual
enrollment/verification work; this module only translates HTTP <-> service calls.
"""

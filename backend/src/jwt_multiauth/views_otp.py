"""OTP-based self-service views: request, verify, resend.

Phase 6 implements the views backing ``urls.py``'s ``/otp/request/``, ``/otp/verify/``,
``/otp/resend/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md`` §5. The magic-link
login variant is a form of ``POST /otp/verify/`` (a link token in place of a code), not a
separate route. ``POST /otp/request/`` for an unregistered identifier on a method NOT in
``USER_FIELDS.AUTO_PROVISION_METHODS`` returns a real-shaped decoy challenge rather than a
``404`` (this repo's ``CLAUDE.md`` rule 5) — never a persisted decoy row (``docs/CONTRACT.md``
§11 item 11, see ``models.py``). For a method IN that list, the same unregistered identifier
instead persists a REAL, ``user=None`` challenge (``docs/CONTRACT.md`` §11 item 19) —
identical response shape either way. ``OtpService`` (``services.py``) does the actual challenge
lifecycle; this module only translates HTTP <-> service calls.
"""

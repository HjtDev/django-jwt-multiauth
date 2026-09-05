"""Self-service contact-verification views: request/confirm.

Phase 8 implements the views backing ``urls.py``'s ``/verify-contact/request/``,
``/verify-contact/confirm/`` routes (basePath ``/api/v1/auth``), per ``docs/CONTRACT.md`` §5 —
proving a caller controls an email/phone value, distinct from that value being used to log in.
``VerificationService`` (``services.py``, Phase 5) does the actual verification-challenge
lifecycle; this module only translates HTTP <-> service calls.
"""

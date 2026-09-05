"""Pure functions, no database access: code/token generation and secret hashing.

Phase 4 implements ``generate_code``, ``generate_link_token``, ``hash_secret``, and
``verify_secret`` — the ONE hashing scheme (HMAC-SHA256, keyed with
``jwt_multiauth.keys.get_otp_pepper()``, compared with ``hmac.compare_digest``, never ``==``) for
every OTP code, link token, recovery code, and trusted-device token in this app
(``docs/CONTRACT.md`` §10). Every generated code/token uses the ``secrets`` module, never
``random`` (this repo's ``CLAUDE.md`` rule 4).

``generate_code`` reads its shape (``LENGTH``, ``ALPHABET``, ``EXCLUDE_AMBIGUOUS``,
``CASE_SENSITIVE``) from ``conf.get_otp_setting(...)`` — never a hardcoded alphabet — and raises
``django.core.exceptions.ImproperlyConfigured`` if the resolved alphabet is empty (e.g. a custom
``ALPHABET`` string with every character excluded by ``EXCLUDE_AMBIGUOUS``), per this repo's
fail-closed rule.
"""

"""Request/response serializers for every self-service and admin view.

Populated alongside each ``views_*``/``admin_views.py`` module as it lands (Phases 6-8), per
``docs/CONTRACT.md`` §5. Explicit field lists throughout — no serializer here ever uses
``fields = "__all__"``, and no response ever exposes a password, a code, a ``code_hash``, a
``token_hash``, or ``secret_encrypted`` (this repo's ``CLAUDE.md`` rule listed under §5).
"""

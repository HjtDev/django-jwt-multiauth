#!/usr/bin/env python
"""Django's ``manage.py``, added in Phase 6 solely to run
``python manage.py spectacular --file schema.yml --fail-on-warn`` against the test host
(``tests.backend.settings``) — this package ships no app of its own to serve, so nothing else
here is expected to be used day-to-day.

Not part of ``pytest``'s own run, so it needs its own ``sys.path`` setup: ``pyproject.toml``'s
``[tool.pytest.ini_options]`` sets ``pythonpath = ["src", ".."]``, but that is a pytest option a
bare ``python manage.py`` invocation never applies — without the two inserts below,
``import tests.backend.settings`` (at repo root, outside ``src/``) would fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_BACKEND_DIR / "src"))
sys.path.insert(0, str(_BACKEND_DIR.parent))


def main() -> None:
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.backend.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and available on your "
            "PYTHONPATH environment variable? Did you forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()

# Local dev/test targets. Every test target brings up docker-compose.test.yml's ephemeral
# Postgres first and tears it down after — a fresh clone needs nothing pre-installed beyond
# Docker and uv. Mirrors ../appkit's and ../cleanup_app's Makefiles. See CLAUDE.md's Commands
# block for the equivalent raw commands.

.PHONY: test test-swapped test-bare lint typecheck frontend-check check sync-readmes docs-link \
	messages compilemessages playground-up playground-down playground-logs playground-reset

# The authoritative gate — celery extra installed, >=85% coverage (this repo's CLAUDE.md
# Commands table). Port 55434, not cleanup_app's 55433 — the two ephemeral Postgres instances
# must not collide if both repos' `make test` run on the same machine at once.
test:
	docker compose -f docker-compose.test.yml up -d --wait
	trap 'docker compose -f docker-compose.test.yml down' EXIT; \
	(cd backend && \
	POSTGRES_HOST=localhost POSTGRES_PORT=55434 \
	POSTGRES_DB=test_dynamic_user POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres \
	uv run --extra celery pytest)

# The fully-swapped leg (this repo's CLAUDE.md Commands table) — proves the swap machinery works
# against tests.backend.settings_swapped's real subclasses, not just the default models. Same
# ephemeral Postgres as `test`; `-k swapped` narrows collection to the swapped-leg test modules
# (each carries its own DJANGO_SETTINGS_MODULE skipif guard as the correctness backstop).
# `--no-cov`: this leg exercises only the swap-specific slice of the codebase by design (the
# DEFAULT leg's own `make test` is the sole >=85% coverage gate, per CLAUDE.md's Commands table)
# — the global --cov-fail-under=85 in addopts would otherwise fail this leg on every green run,
# a pre-existing property of the raw command this target wraps, not something narrower collection
# could fix.
test-swapped:
	docker compose -f docker-compose.test.yml up -d --wait
	trap 'docker compose -f docker-compose.test.yml down' EXIT; \
	(cd backend && \
	POSTGRES_HOST=localhost POSTGRES_PORT=55434 \
	POSTGRES_DB=test_dynamic_user POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres \
	DJANGO_SETTINGS_MODULE=tests.backend.settings_swapped uv run --extra celery pytest -k swapped --no-cov)

# The bare-install leg — no celery extra, no avatar extra, proves the core stands alone.
# `--exact` matters: it removes celery/django-celery-beat/appkit[images] if a prior `make test`
# run left them in the venv. Restores both extras once the bare run finishes, either way — the
# venv is a shared dev environment, not something later targets (or a developer's next command)
# should find in a bare state.
test-bare:
	docker compose -f docker-compose.test.yml up -d --wait
	trap 'docker compose -f docker-compose.test.yml down' EXIT; \
	(cd backend && \
	POSTGRES_HOST=localhost POSTGRES_PORT=55434 \
	POSTGRES_DB=test_dynamic_user POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres \
	uv run --exact pytest -m "not requires_extra" --no-cov; \
	status=$$?; \
	uv sync --extra celery --extra avatar >/dev/null; \
	exit $$status)

# `.` alone silently skips ../tests (a different root) — both are always checked together.
lint:
	cd backend && uv run ruff check . ../tests && uv run ruff format --check . ../tests

typecheck:
	cd backend && uv run mypy src

# The frontend half's own gate — Phase 7's four commands, run at the repo root since
# frontend/ is an npm workspace member (`npm install` here hoists react/@tanstack/react-query
# so the SDK and a host consuming it in the same workspace resolve one copy of each, per
# docs/APP-DESIGN.md §12's "same failure reproduces from a devDependency" note). Regenerating
# types before the diff check catches schema.yml drifting out from under a stale, committed
# schema.d.ts.
frontend-check:
	npm install
	cd frontend && npm run generate:types
	git diff --exit-code frontend/src/schema.d.ts
	cd frontend && npx tsc --noEmit
	cd frontend && npm run lint
	cd frontend && npm run format:check
	cd frontend && npm run test -- --run --coverage
	cd frontend && npm run build
	cd frontend && npm audit --audit-level=high

check: test lint typecheck test-bare frontend-check

# The root README.md is the single hand-maintained source; backend/README.md and
# frontend/README.md are committed, generated copies — PyPI and npm each read a package's
# `readme` file relative to ITS OWN project root, never the repo root, so a monorepo publishing
# from both halves needs a real file in each directory or the registry page shows no
# description at all. CI's `readme-contract` job fails the build if any copy drifts from the
# original — run this and commit the copies whenever README.md changes.
sync-readmes:
	cp README.md backend/README.md
	cp README.md frontend/README.md

# Symlinks the five design docs shared across every project in this ecosystem — APP-DESIGN.md,
# BASE-DESIGN.md, INTEGRATION-GUIDE.md, CLAUDE-CODE-GUIDE-APP.md, CLAUDE-CODE-GUIDE-BASE.md —
# from a sibling checkout of HjtDev/ecosystem-docs, instead of holding a local copy of each.
# Everything else in docs/ (CONTRACT.md, this project's own
# CLAUDE-CODE-GUIDE-APP-DYNAMIC-USER.md, SECURITY-CHECKLIST.md) is untouched — those are
# genuinely local. Idempotent; safe to re-run. See ecosystem-docs/README.md and this repo's own
# CLAUDE.md for the "edit there, never here" convention this depends on.
SHARED_DOCS = APP-DESIGN.md BASE-DESIGN.md INTEGRATION-GUIDE.md CLAUDE-CODE-GUIDE-APP.md \
	CLAUDE-CODE-GUIDE-BASE.md

docs-link:
	@test -d ../ecosystem-docs || { \
		echo "../ecosystem-docs not found — clone it as a sibling of this repo first:" >&2; \
		echo "  cd .. && git clone https://github.com/HjtDev/ecosystem-docs.git" >&2; \
		exit 1; \
	}
	@for f in $(SHARED_DOCS); do \
		rm -f docs/$$f; \
		ln -s ../../ecosystem-docs/$$f docs/$$f; \
	done
	@for f in $(SHARED_DOCS); do \
		test -e docs/$$f || { \
			echo "docs/$$f is a broken symlink — expected ../ecosystem-docs/$$f to exist" >&2; \
			exit 1; \
		}; \
	done
	@echo "Linked $(words $(SHARED_DOCS)) shared docs from ../ecosystem-docs/ (all resolve)"

# Regenerates locale/fa/LC_MESSAGES/django.po from source (admin.py, apps.py, models.py, and
# the Phase 6 admin templates) — new translatable strings land as empty msgstr entries for a
# translator to fill in; existing translations are preserved. Never run on its own before a
# release: compilemessages below must follow, or the .po drifts from the shipped .mo.
messages:
	cd backend/src/dynamic_user && uv run --project ../.. django-admin makemessages -l fa --no-obsolete

# Compiles locale/fa/LC_MESSAGES/django.po into the .mo the wheel-smoke-test CI job (and this
# app's own Jazzmin admin pages) actually read — a .po alone is never enough to ship.
compilemessages:
	cd backend/src/dynamic_user && msgfmt --check locale/fa/LC_MESSAGES/django.po -o locale/fa/LC_MESSAGES/django.mo

# Phase 8 — docs/APP-DESIGN.md §11.2 / docs/CLAUDE-CODE-GUIDE-APP-DYNAMIC-USER.md Phase 8. Run
# from the repo root (docker-compose.yml's build contexts assume it). `npm install`/`frontend`
# build first so the SDK's dist/ is fresh — it's path-linked via the npm workspace, not
# published, so a stale dist/ from a previous checkout would otherwise go unnoticed until a
# frontend container fails at runtime instead of at build. Two hosts, one compose file
# (playground/docker-compose.yml's own header comment explains why one, not two) — `uv sync`
# runs in BOTH host backends before the containers build, same reasoning as frontend's build
# step: each pyproject.toml path-links ../../../backend, and uv.lock must exist and be current
# for `uv sync --no-dev` inside the Dockerfile to reproduce it exactly.
playground-up:
	npm install
	cd frontend && npm run build
	cd playground/default/backend && uv sync
	cd playground/subclassed/backend && uv sync
	docker compose -f playground/docker-compose.yml up -d --build --wait

playground-down:
	docker compose -f playground/docker-compose.yml down

playground-logs:
	docker compose -f playground/docker-compose.yml logs -f

# Re-seeds demo users/profiles/settings on BOTH hosts without tearing the stack down.
playground-reset:
	docker compose -f playground/docker-compose.yml exec backend-default python manage.py seed_users --reset
	docker compose -f playground/docker-compose.yml exec backend-subclassed python manage.py seed_users --reset

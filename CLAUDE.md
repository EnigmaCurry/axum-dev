# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Rust project template for building production web servers with Axum. The repo has two layers:

- **Outer layer** — `setup.sh` and the `template/` directory. This is the instantiation system.
- **Inner layer** — `template/PROJECT/` contains the actual application source. After instantiation, `PROJECT/` is renamed to the app name and `template/` is removed.

The placeholder `${APP}` appears throughout the template and gets replaced with the real app name by `setup.sh`.

## Instantiating a New Project

This is the primary use case for this repo. Run `setup.sh` non-interactively by pre-setting env vars:

```bash
APP="my-app" GIT_FORGE="github.com" GIT_USERNAME="myuser" bash setup.sh
```

Or run `./setup.sh` with no env vars for interactive prompts. The script:
1. Renames `template/PROJECT/` to `template/${APP}/`
2. Runs `envsubst` to replace `${APP}`, `${GIT_FORGE}`, `${GIT_USERNAME}` in all files
3. Copies rendered files to the project root
4. Removes `template/` and `setup.sh`
5. Runs `just deps build test`

After it completes, commit and push the generated files.

## Common Commands

In an instantiated project (or from `template/` when working on the template itself):

```bash
just deps                    # Install dev tools (cargo-nextest, git-cliff, cargo-llvm-cov, sqlx-cli)
just run [ARGS]              # Build and run (e.g., just run help, just run serve)
just build                   # Release build (includes frontend)
just test                    # Run all tests (uses temp SQLite DB)
just test test_name          # Run a single test
just test-verbose test_name  # Single test with log output
just test-watch              # Continuous testing on file change
just clippy                  # Lint (treats warnings as errors)
just clippy --fix            # Auto-fix lints
just migrate                 # Run SQLx migrations on local DB
just test-coverage           # LLVM coverage report
just build-frontend          # Build SvelteKit SPA (pnpm)
```

Tests always use a temporary SQLite database (via `_with-temp-db` helper in Justfile) — never the local dev database.

## Architecture

**Workspace crates** (paths shown as they appear in `template/`; after instantiation, `PROJECT` becomes the app name):
- `PROJECT/` — main binary crate
- `api-doc-macros/` — proc macros for OpenAPI documentation
- `app-macros/` — proc macros for app utilities
- `frontend/` — SvelteKit SPA served as static files by the backend

**Application flow**: `main.rs` → `run_cli()` parses CLI/env config → subcommands (primarily `serve` which calls `server::run()`).

**Configuration** (12-factor, 4-level priority): CLI args > env vars > `~/.local/share/${APP}/defaults.toml` > compiled defaults. Config structs live in `src/config/` with modules for network, database, session, auth, and TLS.

**Key patterns**:
- `AppState` (in `server.rs`) holds `SqlitePool`, `AuthConfig`, and `shutdown_tx` (broadcast channel for SSE shutdown notifications)
- Routes use `aide::axum::ApiRouter` for automatic OpenAPI spec generation
- Middleware stack (Tower-based): `TraceLayer` → `trusted_forwarded_for` → `user_session` → optional OIDC → `csrf_protection` → route-specific layers
- Three auth methods selectable via config: `UsernamePassword`, `ForwardAuth` (reverse proxy), `Oidc`
- Role-based access control via `require_roles_middleware` (e.g., admin routes require `SystemRole::Admin`)
- Five TLS modes: `Http`, `RustlsFiles`, `SelfSigned` (with renewal loop), `AcmeTlsAlpn01`, `AcmeDns01`
- Database: SQLite with WAL mode, migrations in `PROJECT/migrations/`, compile-time checked queries via `sqlx`
- Sessions: SQLite-backed via `tower-sessions` with background expired-session cleanup
- Templates: Askama (Jinja-like) in `PROJECT/templates/`
- API responses wrapped in `ApiResponse<T>` envelope (see `response.rs`)
- SSE endpoint at `/api/events` with shutdown broadcast and 30s keep-alive; server forces exit after 2s deadline to avoid SSE connections blocking shutdown
- Frontend SPA: SvelteKit static build served as fallback route (`/*`)

**Route structure** (in `src/routes/mod.rs`):
- `/api/*` — REST API (CSRF protected)
- `/api/events` — SSE stream (outside CSRF, GET-only)
- `/login/*` — Auth endpoints (CSRF protected)
- `/admin/*` — Admin interface (requires Admin role + CSRF)
- `/docs/*` — OpenAPI docs (Scalar/Redoc/Swagger)
- `/static/*` — Static assets
- `/*` — SvelteKit SPA fallback

## Release Process

For instantiated projects:

```bash
just bump-version   # Creates release-vX.X.X branch with version updates
git push            # Push branch, create PR
# After PR merge:
git checkout master && git pull
just release        # Tags and pushes, triggers GitHub Actions (builds binaries + Docker images)
```

## Merging Changes Back to the Template

From an instantiated project, to push customizations back upstream:

```bash
just merge-template-upstream  # Reverses variable substitution and stages changes in ../rust-axum-template
just new-template-branch      # Test template changes in an orphan branch
```

## Claude Skills

Slash commands available in Claude Code:

- `/create` — Instantiate the template into a new project (prompts for app name, git config, template repo/branch, and location)
- `/dev` — Switch to the `dev` branch, creating or resetting it from `master` as needed
- `/master` — Checkout `master` and pull latest changes
- `/issue` — Create a GitHub issue from a description or conversation context
- `/pr` — Push `dev` and create a PR to `master` (auto-generates title/body from commits)
- `/pr-draft` — Same as `/pr` but creates a draft PR
- `/merge` — Squash-merge the open PR, pull `master`, and clean up `dev`
- `/status` — Show current branch, working tree status, and any open PRs

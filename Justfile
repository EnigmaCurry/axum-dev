set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set export

set dotenv-filename := x'${ENV_FILE:-.env}'
set dotenv-load := true
set dotenv-required := false

FUNCS_SCRIPT := "./_scripts/funcs.sh"
ROOT := justfile_directory()
RUST_LOG        := env_var_or_default("RUST_LOG", "warn")
RUST_BACKTRACE  := env_var_or_default("RUST_BACKTRACE", "1")
RUST_LIB_BACKTRACE  := env_var_or_default("RUST_LIB_BACKTRACE", "1")
GIT_REMOTE      := env_var_or_default("GIT_REMOTE", "origin")
ENV_FILE        := env_var_or_default("ENV_FILE", ".env")
ENV_DIST        := env_var_or_default("ENV_DIST", ".env-dist")
CARGO_PROFILE   := env_var_or_default("CARGO_PROFILE","release")

APP          := "axum-dev"
PROJECT_DIR  := ROOT / APP
MANIFEST     := PROJECT_DIR / "Cargo.toml"
CARGO_TOML   := MANIFEST
CARGO_LOCK   := PROJECT_DIR / "Cargo.lock"
TARGET_DIR   := PROJECT_DIR / "target"

NPM           := env_var_or_default("NPM", "pnpm")
DOCKER        := env_var_or_default("DOCKER", "docker")
DOCKER_IMAGE  := env_var_or_default("DOCKER_IMAGE", "rust-axum-template")
DOCKER_VOLUME := env_var_or_default("DOCKER_VOLUME", "rust-axum-template")
INSTANCE      := env_var_or_default("INSTANCE", "default")
ROOT_DIR      := env_var_or_default("ROOT_DIR", "${APP}-${INSTANCE}-data")
DATABASE_PATH := ROOT_DIR / "{{INSTANCE}}-data.db"

### Container / app environment :::

# Network
NET_LISTEN_IP   := env_var_or_default("NET_LISTEN_IP", "0.0.0.0")
NET_LISTEN_PORT := env_var_or_default("NET_LISTEN_PORT", "3000")
APP_HOST        := env_var_or_default("APP_HOST", "change-me.example.com")

# Authentication / trusted headers
AUTH_TRUSTED_PROXY              := env_var_or_default("AUTH_TRUSTED_PROXY", "127.0.0.1")
# Set auth method: username_password or forward_auth
AUTH_METHOD                     := env_var_or_default("AUTH_METHOD", "username_password")
AUTH_TRUSTED_HEADER_NAME        := env_var_or_default("AUTH_TRUSTED_HEADER_NAME", "X-Forwarded-User")
AUTH_TRUSTED_HEADER_AUTH_GROUP  := env_var_or_default("TRUSTED_HEADER_AUTH_GROUP", "admin")

AUTH_TRUSTED_FORWARDED_FOR      := env_var_or_default("AUTH_TRUSTED_FORWARDED_FOR", "false")
AUTH_TRUSTED_FORWARDED_FOR_NAME := env_var_or_default("AUTH_TRUSTED_FORWARDED_FOR_NAME", "X-Forwarded-For")

# Session
SESSION_SECURE          := env_var_or_default("SESSION_SECURE", "true")
SESSION_EXPIRY_SECONDS  := env_var_or_default("SESSION_EXPIRY_SECONDS", "604800")
SESSION_CHECK_SECONDS   := env_var_or_default("SESSION_CHECK_SECONDS", "60")

# TLS
TLS_MODE := env_var_or_default("TLS_MODE","self-signed")
# Path to TLS certificate (PEM) only used when TLS_MODE=manual.
TLS_CERT_PATH := env_var_or_default("TLS_CERT_PATH","cert.pem")
# Path to TLS private key (PEM) only used when TLS_MODE=manual.
TLS_KEY_PATH := env_var_or_default("TLS_KEY_PATH","key.pem")
# Additional DNS SubjectAltNames (SANs) for the TLS certificate.
# APP_HOST is always used as the primary Common Name (CN).
# Comma-separated list.
TLS_SANS := env_var_or_default("TLS_SANS","")
# ACME challenge type to use: tls-alpn-01, http-01, or dns-01.
TLS_ACME_CHALLENGE := env_var_or_default("TLS_ACME_CHALLENGE","tls-alpn-01")
# ACME directory URL. Default is Let's Encrypt production.
TLS_ACME_DIRECTORY_URL := env_var_or_default("TLS_ACME_DIRECTORY_URL","https://acme-v02.api.letsencrypt.org/directory")
# Contact email for ACME registration.
TLS_ACME_EMAIL := env_var_or_default("TLS_ACME_EMAIL","")
# Validity in days for a self-signed certificate.
TLS_SELF_SIGNED_VALID_DAYS := env_var_or_default("TLS_SELF_SIGNED_VALID_DAYS","3650")
# Directory to store TLS account, certificate, and key data for ACME or self-signed modes.
TLS_CACHE_DIR := env_var_or_default("TLS_CACHE_DIR","./tls-cache")

# print help for Just targets
help:
    @just -l

[private]
_env_init:
    #!/usr/bin/env bash
    set -euo pipefail
    env_file="{{ENV_FILE}}"
    dist_file="{{ENV_DIST}}"
    # resolve relative paths against ROOT
    if [[ "$env_file" != /* ]]; then
      env_path="{{ROOT}}/$env_file"
    else
      env_path="$env_file"
    fi
    if [[ "$dist_file" != /* ]]; then
      dist_path="{{ROOT}}/$dist_file"
    else
      dist_path="$dist_file"
    fi
    if [[ -f "$env_path" ]]; then
      echo "$env_path already exists"
      exit 0
    fi
    if [[ ! -f "$dist_path" ]]; then
      echo "ERROR: $dist_path not found"
      exit 1
    fi
    cp "$dist_path" "$env_path"
    echo "Created $env_path from $dist_path"
    echo "Now re-run your command (dotenv loads on just startup)."

[private]
_env_check:
    #!/usr/bin/env bash
    set -euo pipefail
    env_file="{{ENV_FILE}}"
    if [[ "$env_file" != /* ]]; then
      env_path="{{ROOT}}/$env_file"
    else
      env_path="$env_file"
    fi
    if [[ ! -f "$env_path" ]]; then
      echo "ERROR: $env_path is missing."
      echo "Run: just config ENV_FILE=$env_file"
      exit 1
    fi

# Usage: just _with-temp-db <command>...
[private]
_with-temp-db +cmd:
    #!/usr/bin/env bash
    set -euo pipefail

    tmp_db="$(mktemp "${TMPDIR:-/tmp}/just-db.XXXXXX.sqlite")"
    cleanup() {
        rm -f "$tmp_db" "$tmp_db"-wal "$tmp_db"-shm
    }
    trap cleanup EXIT

    export DATABASE_URL="sqlite://$tmp_db"

    just migrate

    # Run the captured command (from +cmd)
    {{cmd}}


_with-temp-db-script script:
    #!/usr/bin/env bash
    set -euo pipefail

    tmp_db="$(mktemp "${TMPDIR:-/tmp}/just-db.XXXXXX.sqlite")"
    cleanup() { rm -f "$tmp_db" "$tmp_db"-wal "$tmp_db"-shm; }
    trap cleanup EXIT

    export DATABASE_URL="sqlite://$tmp_db"

    just migrate

    bash -c '{{script}}'

# Create .env file from .env-dist (can specify ENV_FILE to override path)
config: _env_init
    @echo "Config check complete for {{ENV_FILE}}."

# Install dependencies
deps:
    @echo
    @echo "Installing dependencies:"
    @echo
    cargo install --locked cargo-nextest
    cargo install --locked git-cliff
    cargo install --locked cargo-llvm-cov
    cargo install --locked sqlx-cli --no-default-features --features sqlite
    @echo
    @echo "All dependencies have been installed."
    @echo
    @echo 'Type `just run` to build and run the development binary, and specify any args after that.'
    @echo 'For example: `just run help`'
    @echo

# Install binary dependencies (gh-actions)
bin-deps:
    cargo binstall --no-confirm cargo-nextest
    cargo binstall --no-confirm git-cliff
    cargo binstall --no-confirm cargo-llvm-cov

# Build and run binary + args
[no-cd]
run *args: _env_check
    cargo run --manifest-path "{{MANIFEST}}" -- {{args}}

# Build + args
build *args: _env_check build-frontend
    just _with-temp-db cargo build --manifest-path "{{MANIFEST}}" {{args}}

# Build continuously on file change
build-watch *args: _env_check
    cd "{{APP}}" && cargo watch -s "clear && just _with-temp-db cargo build --manifest-path {{MANIFEST}} {{args}}"

# Run tests
test *args: _env_check build-frontend
    just _with-temp-db cargo nextest run --manifest-path "{{MANIFEST}}" {{args}}

# Run tests with verbose logging
test-verbose *args: _env_check build-frontend
    just _with-temp-db env RUST_TEST_THREADS=1 \
        cargo nextest run --manifest-path "{{MANIFEST}}" --nocapture {{args}}

# Run tests continuously on file change
test-watch *args: _env_check
    just _with-temp-db-script \
        'cargo watch -C {{PROJECT_DIR}} -s "clear && cargo nextest run --manifest-path \"{{MANIFEST}}\" {{args}}"'

# Run tests continuously with verbose logging
test-watch-verbose *args: _env_check
    just _with-temp-db-script \
        'RUST_TEST_THREADS=1 cargo watch -C {{PROJECT_DIR}} -s "clear && cargo nextest run --manifest-path \"{{MANIFEST}}\" --nocapture -- {{args}}"'

# Build coverage report
test-coverage *args: clean _env_check build-frontend
    just _with-temp-db-script \
        'cargo llvm-cov nextest --manifest-path "{{MANIFEST}}" {{args}} && \
         cargo llvm-cov --manifest-path "{{MANIFEST}}" {{args}} report --html'

# Continuously build coverage report and serve HTTP report
test-coverage-watch *args: _env_check
    just _with-temp-db-script \
        'clear && \
         just test-coverage {{args}} && \
         cd "{{TARGET_DIR}}/llvm-cov/html" && \
         python -m http.server'

# Run Clippy to report and fix lints
clippy *args: _env_check
    RUSTFLAGS="-D warnings" cargo clippy --manifest-path "{{MANIFEST}}" {{args}} --color=always 2>&1 --tests | less -R

# Bump release version and create PR branch
bump-version: _env_check
    @if [ -n "$(git status --porcelain)" ]; then echo "## Git status is not clean. Commit your changes before bumping version."; exit 1; fi
    @if [ "$(git symbolic-ref --short HEAD)" != "master" ]; then echo "## You may only bump the version from the master branch."; exit 1; fi
    source ${FUNCS_SCRIPT}; \
    set -eo pipefail; \
    CURRENT_VERSION=$(grep -Po '^version = \K.*' {{CARGO_TOML}} | sed -e 's/"//g' | head -1); \
    VERSION=$(git cliff --bumped-version | sed 's/^v//'); \
    echo; \
    (if git rev-parse v${VERSION} 2>/dev/null; then \
      echo "New version tag already exists: v${VERSION}" && \
      echo "If you need to re-do this release, delete the existing tag (git tag -d v${VERSION})" && \
      exit 1; \
     fi \
    ); \
    echo "## Current $(grep '^version =' {{CARGO_TOML}} | head -1)"; \
    confirm yes "New version would be \"v${VERSION}\"" " -- Proceed?"; \
    git checkout -B release-v${VERSION}; \
    cargo set-version --manifest-path "{{MANIFEST}}" ${VERSION}; \
    sed -i "s/^VERSION=v.*$/VERSION=v${VERSION}/" README.md; \
    cargo update --manifest-path "{{MANIFEST}}"; \
    git add {{CARGO_TOML}} {{CARGO_LOCK}} README.md; \
    git commit -m "release: v${VERSION}"; \
    echo "Bumped version: v${VERSION}"; \
    echo "Created new branch: release-v${VERSION}"; \
    echo "You should push this branch and create a PR for it."

# Tag and release a new version from master branch
release: _env_check
    @if [ -n "$(git status --porcelain)" ]; then echo "## Git status is not clean. Commit your changes before bumping version."; exit 1; fi
    @if [ "$(git symbolic-ref --short HEAD)" != "master" ]; then echo "## You may only release the master branch."; exit 1; fi
    git remote update;
    @if [[ "$(git status -uno)" != *"Your branch is up to date"* ]]; then echo "## Git branch is not in sync with git remote ${GIT_REMOTE}."; exit 1; fi;
    @set -eo pipefail; \
    source ${FUNCS_SCRIPT}; \
    CURRENT_VERSION=$(grep -Po '^version = \K.*' {{CARGO_TOML}} | sed -e 's/"//g' | head -1); \
    if git rev-parse "v${CURRENT_VERSION}" >/dev/null 2>&1; then echo "Tag already exists: v${CURRENT_VERSION}"; exit 1; fi; \
    if (git ls-remote --tags "${GIT_REMOTE}" | grep -q "refs/tags/v${CURRENT_VERSION}" >/dev/null 2>&1); then echo "Tag already exists on remote ${GIT_REMOTE}: v${CURRENT_VERSION}"; exit 1; fi; \
    cd {{PROJECT_DIR}} && cargo audit; \
    confirm yes "New tag will be \"v${CURRENT_VERSION}\"" " -- Proceed?"; \
    git tag "v${CURRENT_VERSION}"; \
    git push "${GIT_REMOTE}" tag "v${CURRENT_VERSION}";

# Clean all artifacts
clean *args: clean-profile
    cargo clean --manifest-path "{{MANIFEST}}" {{args}}

# Clean profile artifacts only
clean-profile:
    rm -rf {{PROJECT_DIR}}/*.profraw {{PROJECT_DIR}}/*.profdata

# Build svelte frontend
build-frontend: _env_check
    cd frontend && \
    {{NPM}} install && \
    {{NPM}} build

# Build docker image
build-docker: _env_check
    ${DOCKER} build -f {{APP}}/Dockerfile -t ${DOCKER_IMAGE} --build-arg CARGO_PROFILE="{{CARGO_PROFILE}}" .
    echo "Tagged updated image ${DOCKER_IMAGE}"

# Serve the app by itself as a standalone binary
serve *args: _env_check build
    cd {{PROJECT_DIR}} && \
    AUTH_TRUSTED_FORWARDED_FOR=false \
    just run serve {{args}}

# Serve the app in Docker with Traefik and ForwardAuth
serve-docker: _env_check build-docker
    ${DOCKER} run --rm -it \
    --name {{APP}} \
    -v ${DOCKER_VOLUME}:/data \
    -e AUTH_METHOD=forward_auth
    -e RUST_LOG \
    -e RUST_BACKTRACE \
    -e RUST_LIB_BACKTRACE \
    -e NET_LISTEN_IP \
    -e NET_LISTEN_PORT \
    -e AUTH_TRUSTED_PROXY \
    -e AUTH_TRUSTED_HEADER_NAME \
    -e AUTH_TRUSTED_FORWARDED_FOR_NAME \
    -e AUTH_TRUSTED_HEADER_AUTH=true \
    -e AUTH_TRUSTED_FORWARDED_FOR=true \
    -e SESSION_EXPIRY_SECONDS \
    -e SESSION_CHECK_SECONDS \
    -l traefik.enable=true \
    -l traefik.http.routers.{{APP}}.rule=Host\(\`${APP_HOST}\`\) \
    -l traefik.http.routers.{{APP}}.entrypoints=websecure \
    -l traefik.http.routers.{{APP}}.tls=true \
    -l traefik.http.services.{{APP}}.loadbalancer.server.port=${NET_LISTEN_PORT} \
    -l "traefik.http.routers.{{APP}}-login.rule=Host(\`${APP_HOST}\`) && PathPrefix(\`/login\`)" \
    -l traefik.http.routers.{{APP}}-login.entrypoints=websecure \
    -l traefik.http.routers.{{APP}}-login.tls=true \
    -l traefik.http.routers.{{APP}}-login.service={{APP}} \
    -l traefik.http.routers.{{APP}}-login.middlewares=traefik-forward-auth@docker,header-authorization-group-${AUTH_TRUSTED_HEADER_AUTH_GROUP}@file \
    ${DOCKER_IMAGE} serve

# Serve the app in Docker without Traefik
serve-docker-plain: _env_check build-docker
    ${DOCKER} run --rm -it \
    --name {{APP}} \
    -v ${DOCKER_VOLUME}:/data \
    -p ${LISTEN_PORT}:${LISTEN_PORT} \
    -e AUTH_METHOD=username_password \
    -e SESSION_SECURE=false \
    -e RUST_LOG \
    -e RUST_BACKTRACE \
    -e RUST_LIB_BACKTRACE \
    -e NET_LISTEN_IP \
    -e NET_LISTEN_PORT \
    -e SESSION_EXPIRY_SECONDS \
    -e SESSION_CHECK_SECONDS \
    -e AUTH_TRUSTED_FORWARDED_FOR=false \
    ${DOCKER_IMAGE} serve

# Apply database migrations in local database
migrate: _env_check
    cd {{PROJECT_DIR}} && \
    sqlx database create && \
    sqlx migrate run

# Enter sqlite shell of local database
sql:
    cd {{APP}} && sqlite3 {{DATABASE_PATH}}

# Enter sqlite shell of docker database
sql-docker:
    ${DOCKER} exec -it {{APP}} sqlite3 /data/data.db

destroy:
    rm -f {{PROJECT_DIR}}/{{DATABASE_PATH}}

destroy-docker:
    docker rm -fv {{APP}}
    docker volume rm -f {{DOCKER_VOLUME}}

shell:
    docker exec -it {{APP}} /bin/bash

insert-test-data:
    cd {{PROJECT_DIR}} && sqlite3 {{DATABASE_PATH}} < test_data/ryan_user.sql

dev: migrate insert-test-data serve


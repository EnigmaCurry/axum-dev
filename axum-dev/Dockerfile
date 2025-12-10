# Choose "release" or "debug" at build time:
#   docker build -f axum-dev/Dockerfile --build-arg CARGO_PROFILE=debug -t axum-dev:debug .
#   docker build -f axum-dev/Dockerfile --build-arg CARGO_PROFILE=release -t axum-dev:release .
ARG CARGO_PROFILE=release

# ---- Frontend builder (SvelteKit) ---------------------------------
FROM node:22-slim AS frontend-builder

WORKDIR /frontend

# Enable pnpm via corepack (comes with recent Node)
RUN corepack enable

# Copy only lockfile + package.json first for caching
COPY frontend/package.json frontend/pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

# Now copy the rest of the frontend app
COPY frontend ./

# Build the SvelteKit app (adapter-static should output to `build/`)
RUN pnpm build

# 🔍 DEBUG: list what the Svelte build actually produced
RUN echo "=== DEBUG: contents of /frontend after pnpm build ===" && \
    ls -R .

# At this point we expect /frontend/build with static assets


# ---- Rust builder (workspace) ------------------------------------
FROM rust:1.91-slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# sqlx-cli for migrations
RUN cargo install --locked sqlx-cli --no-default-features --features sqlite

# ---------- Pre-fetch Rust dependencies for workspace -------------
# Copy workspace root manifest + lockfile
COPY Cargo.toml Cargo.lock ./

# Copy workspace member manifests
COPY axum-dev/Cargo.toml axum-dev/Cargo.toml
COPY api-doc-macros/Cargo.toml api-doc-macros/Cargo.toml

# Use dummy sources so Cargo can load all workspace members
RUN mkdir -p axum-dev/src api-doc-macros/src && \
    echo "fn main() {}" > axum-dev/src/main.rs && \
    echo "pub fn dummy() {}" > api-doc-macros/src/lib.rs && \
    cargo fetch && \
    rm -rf axum-dev/src api-doc-macros/src

# ---------- Copy full Rust workspace + frontend build -------------
# Now copy the entire repo (workspace) into the container.
# This brings in all crate sources, migrations, etc.
COPY . .

# Copy built frontend into the location Rust expects at compile time.
# For #[folder = "../frontend/build"], from /app/axum-dev this resolves to /app/frontend/build.
COPY --from=frontend-builder /frontend/build ./frontend/build

# 🔍 DEBUG: verify /app/frontend/build contents and fail if index.html is missing
RUN echo "=== DEBUG: contents of /app after copying frontend build ===" && \
    ls -R /app && \
    echo "=== DEBUG: contents of /app/frontend/build ===" && \
    if [ -d /app/frontend/build ]; then \
        ls -R /app/frontend/build; \
    else \
        echo "ERROR: /app/frontend/build directory does not exist"; \
        exit 1; \
    fi && \
    if [ ! -f /app/frontend/build/index.html ]; then \
        echo "ERROR: /app/frontend/build/index.html is missing"; \
        exit 1; \
    fi

# Now build the Rust binary (from workspace root, targeting axum-dev)
WORKDIR /app/axum-dev

ENV DATABASE_URL=sqlite:test.db

ARG CARGO_PROFILE
RUN sqlx database create && sqlx migrate run && \
    if [ "$CARGO_PROFILE" = "release" ]; then \
        echo "Building release profile"; \
        cargo build --release --locked -p axum-dev; \
    elif [ "$CARGO_PROFILE" = "debug" ]; then \
        echo "Building debug profile"; \
        cargo build --locked -p axum-dev; \
    else \
        echo "Unknown CARGO_PROFILE='$CARGO_PROFILE' (expected 'release' or 'debug')" >&2; \
        exit 1; \
    fi


# ---- Runtime -------------------------------------------------
FROM debian:trixie-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/enigmacurry/axum-dev"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates coreutils sqlite3 && \
    rm -rf /var/lib/apt/lists/*

ARG USER=appuser UID=1001 GID=1001
RUN groupadd --gid "$GID" "$USER" \
 && useradd  --uid "$UID" \
             --gid "$GID" \
             --create-home \
             --shell /usr/sbin/nologin \
             "$USER"

# Re-declare build arg in this stage so we can use it in COPY
ARG CARGO_PROFILE

COPY --from=builder /app/target/${CARGO_PROFILE}/axum-dev /usr/local/bin/axum-dev

RUN mkdir /data && chown ${USER} /data
VOLUME /data

ENV ROOT_DIR=/data NET_LISTEN_IP=0.0.0.0 NET_LISTEN_PORT=3000

USER $USER

ENTRYPOINT ["axum-dev"]

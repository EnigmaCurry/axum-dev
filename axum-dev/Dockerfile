# Choose "release" or "debug" at build time:
#   docker build --build-arg CARGO_PROFILE=debug -t axum-dev:debug .
#   docker build --build-arg CARGO_PROFILE=release -t axum-dev:release .
ARG CARGO_PROFILE=release

# ---- Builder -------------------------------------------------
FROM rust:1.91-slim-trixie AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN cargo install --locked sqlx-cli --no-default-features --features sqlite

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo fetch && rm -rf src

COPY . .

ENV DATABASE_URL=sqlite:test.db

ARG CARGO_PROFILE
RUN sqlx database create && sqlx migrate run && \
    if [ "$CARGO_PROFILE" = "release" ]; then \
        echo "Building release profile"; \
        cargo build --release --locked; \
    elif [ "$CARGO_PROFILE" = "debug" ]; then \
        echo "Building debug profile"; \
        cargo build --locked; \
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

ENV DATABASE_URL=sqlite:///data/data.db \
    LISTEN_IP=0.0.0.0 \
    LISTEN_PORT=3000

USER $USER

ENTRYPOINT ["axum-dev"]

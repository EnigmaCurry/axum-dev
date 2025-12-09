# axum-dev

[![Crates.io](https://img.shields.io/crates/v/axum-dev?color=blue
)](https://crates.io/crates/axum-dev)
[![Coverage](https://img.shields.io/badge/Coverage-Report-purple)](https://enigmacurry.github.io/axum-dev/coverage/master/)

## Features

 * Single binary deployment.
 * Embedded SQLite database.
 * RESTFul JSON API built with
   [axum](https://github.com/tokio-rs/axum).
 * Builtin TLS with the following modes:
   * ACME supporting TLS-ALPN-01 and DNS-01 challenge types. (e.g.,
     when you need a production certificate from Let's Encrypt.)
   * Automatic TLS with self-signed certificate (e.g., when using
     certificate pinning).
   * TLS with a provided certificate and key file (e.g., `.pem` files
     that you rotate manually).
   * None (plain HTTP) (e.g., when deployed behind a reverse proxy
     that terminates TLS on its behalf).
 * OpenAPI specification built with
   [aide](https://github.com/tamasfe/aide/).
 * Interactive API docs with your choice of
   [Scalar](https://github.com/ScalaR/ScalaR),
   [Redoc](https://github.com/Redocly/redoc), or [Swagger
   UI](https://github.com/swagger-api/swagger-ui?tab=readme-ov-file).
 * Multiple user authentication backends:
   * Username / Password.
   * Forward Auth via trusted header (Traefik Proxy or compatible proxy layer).
   * Todo: OAuth (OIDC).
 * Admin web interface.
 * [Just](https://github.com/casey/just) enabled project build
   targets.
 * [Clap](https://docs.rs/clap/latest/clap/) CLI argument parser.
 * Bash / Fish / Zsh shell (tab)
   [completion](https://docs.rs/clap_complete/latest/clap_complete/).
 * GitHub actions for tests and releases:
   * Builds executables for multiple platforms.
   * Builds Docker images for x86_64 and aarch64.
   * Test coverage report published to GitHub pages.
   * Publishing crates to crates.io (disabled by default, uncomment in
   [release.yml](template/.github/workflows/release.yml)).

## Build

```
just build --release
```

Find your built executable in `target/release/axum-dev`.

## Install

```
sudo install \
  target/release/axum-dev \
  /usr/local/bin/axum-dev
```

## Run

Run `axum-dev --help` to find all the options, but broadly speaking
there are a few ways you can run it:

### Plain HTTP

You should always use TLS, so only use plain HTTP if you are hosting
behind a reverse proxy that terminates TLS for you:

```
export NET_HOST=axum-dev.example.org
export NET_LISTEN_IP=0.0.0.0
export NET_LISTEN_PORT=80
export DATABASE_URL=sqlite:data.db
export AUTH_METHOD=username_password
export SESSION_SECURE=false
export RUST_LOG=axum_dev=info

axum-dev serve
```

### Manual TLS

```
export NET_HOST=axum-dev.example.org
export NET_LISTEN_IP=0.0.0.0
export NET_LISTEN_PORT=443
export DATABASE_URL=sqlite:data.db
export AUTH_METHOD=username_password
export SESSION_SECURE=true
export TLS_MODE=manual
export TLS_CERT_PATH=cert.pem
export TLS_KEY_PATH=key.pem
export RUST_LOG=axum_dev=info

axum-dev serve
```

### ACME (TLS-ALPN-01)

```
export NET_HOST=axum-dev.example.org
export TLS_SANS=
export NET_LISTEN_IP=0.0.0.0
export NET_LISTEN_PORT=443
export DATABASE_URL=sqlite:data.db
export AUTH_METHOD=username_password
export SESSION_SECURE=true
export TLS_MODE=acme
export TLS_ACME_CHALLENGE=tls-alpn-01
export TLS_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export TLS_ACME_EMAIL=
export RUST_LOG=axum_dev=info

axum-dev serve
```

### ACME (DNS-01 via ACME-DNS)

```
export NET_HOST=axum-dev.example.org
export TLS_SANS=
export NET_LISTEN_IP=0.0.0.0
export NET_LISTEN_PORT=443
export DATABASE_URL=sqlite:data.db
export AUTH_METHOD=username_password
export SESSION_SECURE=true
export TLS_MODE=acme
export TLS_ACME_CHALLENGE=dns-01
export TLS_ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export TLS_ACME_EMAIL=
export ACME_DNS_API_BASE=https://auth.acme-dns.io
export RUST_LOG=axum_dev=info

## Register ACME-DNS account 
## Follow the instructions it gies to create CNAME records:
axum-dev acme-dns-register

## Loads ACME-DNS credentials and provisions cert on first run:
axum-dev serve
```

### Self-Signed TLS

```
export NET_HOST=axum-dev.example.org
export NET_LISTEN_IP=0.0.0.0
export NET_LISTEN_PORT=443
export DATABASE_URL=sqlite:data.db
export AUTH_METHOD=username_password
export SESSION_SECURE=true
export TLS_MODE=self-signed
export RUST_LOG=axum_dev=info

axum-dev serve
```

## Development

For development, you are advised to install
[just](https://github.com/casey/just) and use the targets defined in
the [Justfile](Justfile).

## Configure the .env file

```
just config
```

This will copy the provided [.env-dist](template/.env-dist) to `.env`.
You should edit the generated `.env` file by hand to configure your
application.

You can set an alternative `.env` file path by setting the `ENV_FILE`
environment variable.

## Run the program

```
just run [ARGS ...]
```

You can also run the binary directly by building manually (`just
build`) and running the static binary
`{{app_name}}/target/debug/{{app_name}}`.

Also see [DEVELOPMENT.md](DEVELOPMENT.md)

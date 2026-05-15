# rust-axum-template

An [Axum](https://github.com/tokio-rs/axum) server template for new Rust web projects. Includes SQLite, TLS (ACME/self-signed), OpenAPI docs, multiple auth backends, SvelteKit frontend, and GitHub Actions CI/CD.

For the full feature list, see the [template README](template/README.md).

## Quick Start with an AI Agent

If you have an AI coding agent (Claude Code, Cursor, Copilot, etc.), you can create a new project with a prompt like:

> Clone https://github.com/EnigmaCurry/rust-axum-template to a
> directory named after my new project, then use the included `/create`
> skill or follow the CLAUDE.md instructions to instantiate it.

## Manual Setup

### Prerequisites

 * [Rust](https://rustup.rs/) (via rustup)
 * [Just](https://github.com/casey/just?tab=readme-ov-file#packages) (`cargo install just`)
 * [pnpm](https://pnpm.io/installation) (for the SvelteKit frontend)
 * `envsubst` (e.g., `sudo apt install gettext`)

### Create from GitHub template

 * [Create a new repository using this template](https://github.com/new?template_name=rust-axum-template&template_owner=EnigmaCurry).
 * The repository name you choose will become your app name.
 * In your repo's Settings > Pages > Source, set it to **GitHub Actions**.

### Clone and render

```bash
git clone <your-new-repo-url>
cd <your-app-name>
./setup.sh
```

The script will prompt for:

 * **GIT_FORGE** — your git host domain (default: `github.com`)
 * **APP** — application name (alphanumeric with dashes, no spaces)
 * **GIT_USERNAME** — git forge username or org name

It renders the template, builds the frontend, compiles the binary, and runs tests.

You can also run it non-interactively:

```bash
APP="my-app" GIT_FORGE="github.com" GIT_USERNAME="myuser" ./setup.sh
```

## After Setup

Once the build and tests pass, commit the generated files:

```bash
git add .
git commit -m "init"
git push
```

Run `just run help` to see available commands, or `just serve` to start the server.

## Development & Releases

See [DEVELOPMENT.md](template/DEVELOPMENT.md) for testing, linting, and the release process.

# Development

## Install host dependencies

These instructions are specific to Fedora; minor adjustments for your
platform may be required.

```
sudo dnf install git openssh rustup
sudo dnf install @development-tools @development-libs
```

## Install rust and cargo

```
rustup-init ## just press enter when prompted for default selection
. "$HOME/.cargo/env"
```

## Clone source repository

```
git clone git@github.com:enigmacurry/axum-dev.git \
  ~/git/vendor/enigmacurry/axum-dev
cd ~/git/vendor/enigmacurry/axum-dev
```

## Install development dependencies

```
cargo install just
just deps
```

## Build and run development axum-dev

```
just run help
just run [ARGS ...]
```

## Build release binary

```
just build --release
```

## Create development alias

```
## Add this to ~/.bashrc or equivalent:
alias axum-dev='just -f ~/git/vendor/enigmacurry/axum-dev/Justfile run'
source <(axum-dev completions bash 2> /dev/null)
```

Now you can run `axum-dev` from any directory, with
any arguments, and it will automatically rebuild from source, and then
run it with those args. This will have full tab-completion in your shell.

## Configure the .env file

In development only, when using the `just` command, you will use the
`.env` file. You need to generate it from the included `.env-dist`:

```
just config
```

This will copy the provided [.env-dist](template/.env-dist) to `.env`.
You should edit the generated `.env` file by hand to configure your
application.

You can set an alternative `.env` file path by setting the `ENV_FILE`
environment variable.

It is important to know that the program itself does not know how to
read `.env` files. It is `just` that is loading the .env file and
setting regular environment variables, which the program can read.
`just` and `.env` files are only used during development.

## Run the program

```
# Compile and run on the fly with `just`:

just run [ARGS ...]

# OR, from the compiled binary:

axum-dev [ARGS ..]
```

## Testing

This project has incomplete testing. [See the latest coverage
report](https://enigmacurry.github.io/axum-dev/coverage/master/).

## Run tests

```
# Run all tests:
just test

# Run a single test:
just test test_cli_help

# Verbose logging (which normally would be hidden for passing tests)
just test-verbose test_cli_help

# Auto run tests on source change:
just test-watch
```

## Clippy

```
just clippy
just clippy --fix
```

## Reverse template

If you are developing in a repository that is an instance of this
template, and you want to merge your changes back upstream:

 * Make sure you have cloned rust-axum-template as a sibling
   repository of the current project (i.e., `../rust-axum-template`).
 * Make sure both this and the other repository has a clean git status
   (the script will check for this).

```
just merge-template-upstream
```

This will copy all the changes from the current project directory into
the template directory (`../rust-axum-template/template`),
automatically reversing the project name (e.g., `axum-foo`) back into
the original template var `axum-dev` in the same files that the
template's setup.sh modified via `envsubst`. Finally it will git stage
all the changes, ready to be commited to the rust-axum-template
repository.

## Test new template branch

If you want to test the new template changes, without needing to
create a new repository, you may re-instantiate the template into a
new orphan branch of the same repository:

```
just new-template-branch
```

It will ask you for the name of the new branch, which will be copied
from the local `../rust-axum-template` repository.

## Release (Github actions)

### Install cargo dependencies

```
just deps
```

### Bump release version and push new branch

The `bump-version` target will automatically update the version number
in Cargo.toml, Cargo.lock, and README.md as suggested by git-cliff.
This creates a new branch named `release-{VERSION}`, and automatically
checks it out. You just need to `git push` the branch:

```
just bump-version
# ... automatically checks out a new branch named release-{VERSION}

git push
```

### Make a new PR with the changeset

Branch protection should be enabled, and all changesets should come in
the form of a Pull Request. On GitHub, create a new Pull Request for
the `release-{VERSION}` branch into the master branch.

### Merge the PR and tag the release

Once the PR is merged, update your local repo, and run the release
target:

```
git checkout master
git pull
just release
```

New binaries will be automatically built by github actions, and a new
packaged release will be posted.

## Publish crates to crates.io

In [release.yml](.github/workflows/release.yml) there is a commented
out section for publishing to crates.io automatically on release.
Simply uncomment to enable it.

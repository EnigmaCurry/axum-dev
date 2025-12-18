# rust-axum-template

This is my [Axum](https://github.com/tokio-rs/axum) server template for new
Rust web projects.

This is ALPHA software in-development.

## Features

For the full list of features, see the embedded
[README.md](template/README.md) inside the template.

## How to use this template

 * [Create a new repository using this template](https://github.com/new?template_name=rust-axum-template&template_owner=EnigmaCurry).
 * The `Repository name` that you choose will also become the name of
   your new app.
 * Go to the GitHub repository `Settings` page:
   * Find `Pages`.
   * Find `Build and deployment`.
   * Find `Source` and set it to `GitHub Actions`. (**Not** `Deploy
     from a branch`)

## On your workstation ...

 * Clone your new repository.
 * Install Rust with [rustup](https://rustup.rs/).
 * Install
     [Just](https://github.com/casey/just?tab=readme-ov-file#packages).
     (You can run `cargo install just`.)
 * Install [pnpm](https://pnpm.io/installation) (to build SvelteKit
   frontend SPA).
 * Install `envsubst`. (e.g., `sudo apt install gettext`)

### Render the template

After cloning the repository to your workstation, you must initialize
 it. Run `setup.sh`:

```
./setup.sh
```

Read the interactive prompts and enter the following information:

 * `GIT_FORGE` - enter your Git host's domain name (e.g.,
   `github.com`).
 * `APP` - enter your new application's name. Use alphanumeric
   characters with dashes. No spaces.
 * `GIT_USERNAME` - enter the Git forge username or the organization
   name that should host this repository.

This will render the template files into the project root and then
self-destruct this README.md and the template.

Cargo will build and run the initial tests.

### Commit the initial app source files

Once you've verified that the tests ran correctly, you can add all of
the files that the template generated, as well as the `Cargo.lock`
file, into the git repository. Commit and push your changes:

```
## For example:

git add .
git commit -m "init"
git push
```

You're now ready to start developing your application.

## Diff current project with the template

Sometimes it's useful to show all of the changes to the project since
the template was initialized. When you created the project from the
template, it created the first commit containing all of the template
files. You can use git diff to figure out the changeset. The Justfile
wraps these commands for you:

```
## List only the names of the files added/modified since init:
just template-changelog

## List the full diff between the current state and first commit:
just template-diff

## List the differences of a couple of files:
just template-diff Cargo.toml README.md
```

## Releasing your app

See [DEVELOPMENT.md](template/DEVELOPMENT.md) for instructions on the
release process, a copy of this file has been included in your new git
repository's root.
 

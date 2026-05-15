---
name: create
description: "Instantiate the rust-axum-template into a new project"
allowed-tools: Bash, AskUserQuestion, Read
---

# Create a new project from the rust-axum-template

## Arguments

Parse `$ARGUMENTS` for the following values. Arguments may be passed positionally
(`/create my-app github.com acme`) or as `key=value` pairs
(`/create app=my-app git_username=acme`). Skip prompts for any value already provided.

- **APP** (1st positional or `app=`): Project name (alphanumeric and hyphens only)
- **GIT_FORGE** (2nd positional or `git_forge=`): Git forge domain (default: `github.com`)
- **GIT_USERNAME** (3rd positional or `git_username=`): Git forge username or org name
- **DEPS_TARGET** (`deps_target=`): Dependency install target (default: `bin-deps`)

Only ask about template repo and branch if the user mentioned them:
- **TEMPLATE_REPO**: `https://github.com/EnigmaCurry/rust-axum-template.git`
- **TEMPLATE_BRANCH**: `master`

## Instructions

1. **Check for nix-shell.** If `nix-shell` is on `$PATH`, all bash commands in the
   steps below MUST be run inside `nix-shell`. Use `nix-shell --run "<command>"` for
   each bash invocation. The repo's `shell.nix` provides all required build tools
   (cargo, node, pnpm, just, pkg-config, openssl, etc.) and configures environment
   variables automatically. Do NOT install packages individually via `nix profile install`.

2. For any required value not provided via arguments, ask the user with AskUserQuestion:
   - For **APP**: offer a default based on the current directory name as the first option, with a second descriptive option like "Enter a custom name" (select Other to type one)
   - For **GIT_FORGE**: offer `github.com` (Recommended) and `codeberg.org` as options
   - For **GIT_USERNAME**: offer the username parsed from `git remote get-url origin` as default, with "Enter a different username" as the second option

3. Ask whether to:
   - **a)** Transform the current repository in-place (run `setup.sh` here) (Recommended)
   - **b)** Create a new project directory elsewhere

4. If creating a new directory (option b):
   ```bash
   NEW_DIR="../${APP}"
   git clone --branch "${TEMPLATE_BRANCH}" "${TEMPLATE_REPO}" "${NEW_DIR}"
   ```
   Then run setup.sh from inside that directory.

5. Run setup.sh non-interactively (remember: wrap in `nix-shell --run` if nix is available):
   ```bash
   cd "${PROJECT_DIR}"
   DEPS_TARGET="${DEPS_TARGET}" APP="${APP}" GIT_FORGE="${GIT_FORGE}" GIT_USERNAME="${GIT_USERNAME}" bash setup.sh
   ```

6. Verify the build succeeded:
   ```bash
   just test
   ```
   All tests should pass. If they fail, diagnose and fix before continuing.

7. Report success and remind the user to:
   - Review `LICENSE.txt`
   - Run `just run help` to verify the build

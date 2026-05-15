#!/bin/bash
set -e

# Directory of the script
ROOT_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
TEMPLATE_DIR="$ROOT_DIR/template"

cd ${ROOT_DIR}
source _scripts/funcs.sh
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
debug_var ROOT_DIR

check_deps cargo just pnpm envsubst sed

# Verify we have GNU envsubst (supports SHELL-FORMAT allowlist).
# The Go-based a8m/envsubst ignores the allowlist and corrupts template files.
if ! envsubst --help 2>&1 | grep -q SHELL-FORMAT; then
    echo "ERROR: envsubst on PATH is not GNU gettext envsubst."
    echo "The Go-based envsubst (a8m/envsubst) does not support SHELL-FORMAT"
    echo "and will corrupt template files. Install GNU gettext instead."
    echo "  Nix: use 'gettext' package, not 'envsubst'"
    exit 1
fi

# Non-interactive mode: if APP, GIT_FORGE, and GIT_USERNAME are all set,
# skip prompts and confirmation. Set NONINTERACTIVE=1 to also skip the
# final confirmation automatically.
if [[ -n "${APP:-}" && -n "${GIT_FORGE:-}" && -n "${GIT_USERNAME:-}" ]]; then
    NONINTERACTIVE=1
fi

if [[ "${NONINTERACTIVE:-}" != "1" ]]; then
    echo
    ask_no_blank "Enter your git forge domain (e.g. forgejo.example.com or github.com)" GIT_FORGE "github.com"

    _DEFAULT_APP="$(basename "$ROOT_DIR")"
    _DEFAULT_APP="$(printf '%s' "$_DEFAULT_APP" | sed -E 's/[^[:alnum:]-]+/-/g')"
    echo
    ask_no_blank "Enter your application name (no spaces)" APP "${APP:-${_DEFAULT_APP}}"

    _DEFAULT_USERNAME="$(
            git remote get-url origin 2>/dev/null |
              sed -E 's/^(https:\/\/|git@github\.com:)([^\/]+).*$/\2/')"
    _DEFAULT_USERNAME="${_DEFAULT_USERNAME,,}"
    echo
    ask_no_blank "Enter your Git forge username or org name" GIT_USERNAME "${GIT_USERNAME:-${_DEFAULT_USERNAME}}"
fi

export APP
export GIT_FORGE="${GIT_FORGE:-github.com}"
export GIT_USERNAME="${GIT_USERNAME,,}"
export APP_PREFIX=${APP^^}
APP_PREFIX="${APP_PREFIX//[ -]/_}"   # space/dash -> underscore
APP_PREFIX="${APP_PREFIX##_}"        # trim leading underscores
APP_PREFIX="${APP_PREFIX%%_}"        # trim trailing underscores
APP_PREFIX="${APP_PREFIX}_"          # append final underscore
export APP_MODULE="${APP_PREFIX,,}"
export GIT_REPOSITORY="https://${GIT_FORGE}/${GIT_USERNAME}/${APP}"

echo
check_var APP GIT_USERNAME
debug_var APP
debug_var GIT_USERNAME
debug_var GIT_REPOSITORY

if [[ "${NONINTERACTIVE:-}" != "1" ]]; then
    echo
    echo "Cargo will now download extra dependencies, build, and test your app."
    confirm yes "Do you want to proceed with the values shown above" "?"
fi

# Rename PROJECT directory to the same name as the app
mv "${TEMPLATE_DIR}/PROJECT" "${TEMPLATE_DIR}/${APP}"

# Copy files recursively and replace variables
while IFS= read -r -d '' file; do
    # Determine relative path and destination path
    REL_PATH="${file#$TEMPLATE_DIR/}"
    DEST_PATH="$ROOT_DIR/$REL_PATH"

    # Create destination directory if it doesn't exist
    mkdir -p "$(dirname "$DEST_PATH")"

    # Remove any existing symlink at destination (otherwise > follows the
    # symlink and overwrites the source file, leaving a dangling link after
    # rm -rf template)
    [[ -L "$DEST_PATH" ]] && rm -f "$DEST_PATH"

    # Replace variables using envsubst and copy the file
    envsubst '${APP} ${APP_PREFIX} ${APP_MODULE} ${GIT_FORGE} ${GIT_USERNAME} ${GIT_REPOSITORY}' < "$file" > "$DEST_PATH"
    echo "Processed: $file -> $DEST_PATH"
done < <(find "$TEMPLATE_DIR" -type f -print0)

echo "Template render complete!"
rm -rf template setup.sh

# Point origin at the new project's repository
git remote set-url origin "${GIT_REPOSITORY}.git"
echo "Set git remote origin to ${GIT_REPOSITORY}.git"

# If running inside nix-shell, native deps (openssl, pkg-config) are already
# available. Otherwise, if nix is on PATH and shell.nix exists, wrap the build
# in nix-shell so cargo can find native libraries.
_build_cmd="just ${DEPS_TARGET:-deps} build && just test"

if [[ -n "${IN_NIX_SHELL:-}" ]]; then
    eval "$_build_cmd"
elif command -v nix-shell &>/dev/null && [[ -f "${ROOT_DIR}/shell.nix" ]]; then
    echo "Detected nix — running build inside nix-shell for native dependencies..."
    nix-shell "${ROOT_DIR}/shell.nix" --run "$_build_cmd"
else
    eval "$_build_cmd"
fi

git add .
git add -f .env-dist

echo "Please review the license terms in LICENSE.txt"

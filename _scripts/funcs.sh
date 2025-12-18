#!/bin/bash

stderr(){ echo "$@" >/dev/stderr; }
error(){ stderr "Error: $@"; }
fault(){ test -n "$1" && error $1; stderr "Exiting."; exit 1; }
cancel(){ stderr "Canceled."; exit 2; }
exe() { (set -x; "$@"); }
print_array(){ printf '%s\n' "$@"; }
trim_trailing_whitespace() { sed -e 's/[[:space:]]*$//'; }
trim_leading_whitespace() { sed -e 's/^[[:space:]]*//'; }
trim_whitespace() { trim_leading_whitespace | trim_trailing_whitespace; }
check_var(){
    local __missing=false
    local __vars="$@"
    for __var in ${__vars}; do
        if [[ -z "${!__var}" ]]; then
            error "${__var} variable is missing."
            __missing=true
        fi
    done
    if [[ ${__missing} == true ]]; then
        fault
    fi
}

check_num(){
    local var=$1
    check_var var
    if ! [[ ${!var} =~ ^[0-9]+$ ]] ; then
        fault "${var} is not a number: '${!var}'"
    fi
}

debug_var() {
    local var=$1
    check_var var
    stderr "## DEBUG: ${var}=${!var}"
}

debug_array() {
    local -n ary=$1
    echo "## DEBUG: Array '$1' contains:"
    for i in "${!ary[@]}"; do
        echo "## ${i} = ${ary[$i]}"
    done
}

ask() {
    ## Ask the user a question and set the given variable name with their answer
    local __prompt="${1}"; local __var="${2}"; local __default="${3}"
    read -e -p "${__prompt}"$'\x0a: ' -i "${__default}" ${__var}
    export ${__var}
}

ask_no_blank() {
    ## Ask the user a question and set the given variable name with their answer
    ## If the answer is blank, repeat the question.
    local __prompt="${1}"; local __var="${2}"; local __default="${3}"
    while true; do
        read -e -p "${__prompt}"$'\x0a: ' -i "${__default}" ${__var}
        export ${__var}
        [[ -z "${!__var}" ]] || break
    done
}

ask_echo() {
    ## Ask the user a question then print the non-blank answer to stdout
    (
        ask_no_blank "$1" ASK_ECHO_VARNAME >/dev/stderr
        echo "${ASK_ECHO_VARNAME}"
    )
}

require_input() {
    ## require_input {PROMPT} {VAR} {DEFAULT}
    ## Read variable, set default if blank, error if still blank
    test -z ${3} && dflt="" || dflt=" (${3})"
    read -e -p "$1$dflt: " $2
    eval $2=${!2:-${3}}
    test -v ${!2} && fault "$2 must not be blank."
}

make_var_name() {
    # Make an environment variable out of any string
    # Replaces all invalid characters with a single _
    echo "$@" | sed -e 's/  */_/g' -e 's/--*/_/g' -e 's/[^a-zA-Z0-9_]/_/g' -e 's/__*/_/g' -e 's/.*/\U&/' -e 's/__*$//' -e 's/^__*//'
}

confirm() {
    ## Confirm with the user.
    local default=$1; local prompt=$2; local question=${3:-". Proceed?"}
    check_var default prompt question
    if [[ $default == "y" || $default == "yes" || $default == "ok" ]]; then
        dflt="Y/n"
    else
        dflt="y/N"
    fi
    read -e -p "${prompt}${question} (${dflt}): " answer
    answer=${answer:-${default}}
    if [[ ${answer,,} == "y" || ${answer,,} == "yes" || ${answer,,} == "ok" ]]; then
        return 0
    else
        return 1
    fi
}
check_deps() {
    missing=""
    for var in "$@"; do
        echo -n "Looking for ${var} ... " >/dev/stderr
        if ! command -v "${var}" >/dev/null 2>&1; then
            echo "Missing! No ${var} found in PATH." >/dev/stderr
            missing="${missing} ${var}"
        else
            echo found $(which "${var}")
        fi
    done

    if [[ -n "${missing}" ]]; then fault "Missing dependencies: ${missing}"; fi
}
check_emacs_unsaved_files() {
    lock_files=$(find . -name ".#*")
    if [ ! -z "$lock_files" ]; then
        echo "Warning: You have unsaved files in Emacs. Please save all files before building."
        echo "Unsaved files:"
        echo "$lock_files"
        return 1
    fi
}

template_changelog_files() {
  set -euo pipefail

  local base
  base="$(git rev-list --reverse --first-parent HEAD | head -n1)"

  # Skip set: files that were purely moved/copied out of template/ with no content changes.
  local -A skip=()
  while IFS=$'\t' read -r status old new; do
    case "$status" in
      R100|C100)
        [[ "$old" == template/* ]] && skip["$new"]=1
        ;;
    esac
  done < <(git diff --name-status -M --diff-filter=RC "${base}..HEAD")

  git diff --name-only --diff-filter=AMCR "${base}..HEAD" \
    | LC_ALL=C sort -u \
    | while IFS= read -r f; do
        # Drop pure moves from template/ (unchanged content)
        [[ -n "${skip[$f]:-}" ]] && continue

        # Find a base path to compare against (handles template/ -> root move)
        local base_path=""
        if git cat-file -e "${base}:${f}" 2>/dev/null; then
          base_path="$f"
        elif git cat-file -e "${base}:template/${f}" 2>/dev/null; then
          base_path="template/${f}"
        fi

        # If not present in base at either location, treat as new/unknown -> include
        if [[ -z "$base_path" ]]; then
          printf '%s\n' "$f"
          continue
        fi

        case "$f" in
          .env-dist)
            # Ignore if ONLY these keys changed (values may differ)
            if (diff -U0 <(git show "${base}:${base_path}") "$f" || true) \
              | awk '
                  /^--- /    { next }
                  /^\+\+\+ / { next }
                  /^@@/      { next }
                  /^[+-]/ {
                    line = substr($0, 2)
                    if (line ~ /^(ROOT_DIR|DOCKER_IMAGE)=/) next
                    exit 1
                  }
                  END { exit 0 }
                '
            then
              continue
            fi
            ;;
        esac

        printf '%s\n' "$f"
      done
}

template_diff() {
  set -euo pipefail
  local base
  base="$(git rev-list --reverse --first-parent HEAD | head -n1)"

  # If paths are provided, treat them as a whitelist, but also include template/… paths
  if (($#)); then
    local -A seen=()
    local -a paths=()
    local p alt

    for p in "$@"; do
      # include exactly what user typed
      if [[ -z "${seen[$p]:-}" ]]; then paths+=("$p"); seen["$p"]=1; fi

      # include the "other side" so renames/moves can be shown
      if [[ "$p" == template/* ]]; then
        alt="${p#template/}"        # template/foo -> foo
      else
        alt="template/$p"           # foo -> template/foo
      fi
      if [[ -z "${seen[$alt]:-}" ]]; then paths+=("$alt"); seen["$alt"]=1; fi

      # Optional: if you export APP, also map APP/... to template/PROJECT/...
      if [[ -n "${APP:-}" && "$p" == "axum-dev/"* ]]; then
        alt="template/PROJECT/${p#axum-dev/}"
        if [[ -z "${seen[$alt]:-}" ]]; then paths+=("$alt"); seen["$alt"]=1; fi
      fi
    done

      git -c color.ui=always diff -M "${base}..HEAD" -- "${paths[@]}" | less -RSX
  else
      git -c color.ui=always diff -M "${base}..HEAD" | less -RSX
  fi
}

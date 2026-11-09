#!/usr/bin/env bash
## Shared shell helpers for the Justfile.

check_var() {
    local __missing=false
    local __vars="$*"
    for __var in ${__vars}; do
        if [[ -z "${!__var:-}" ]]; then
            echo "${__var} is missing." >/dev/stderr
            __missing=true
        fi
    done
    if [[ ${__missing} == true ]]; then
        return 1
    fi
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
    local missing=""
    for var in "$@"; do
        if ! command -v "${var}" >/dev/null 2>&1; then
            missing="${missing} ${var}"
        fi
    done
    if [[ -n "${missing}" ]]; then
        echo "Missing required tools:${missing}" >/dev/stderr
        echo "Run \`just deps\`, or enter the dev shell with \`nix develop\`." >/dev/stderr
        return 1
    fi
}

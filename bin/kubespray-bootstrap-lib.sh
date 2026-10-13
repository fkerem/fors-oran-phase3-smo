#!/bin/sh
# Pure helpers: callers supply explicit paths and selected source revisions.

phase3_kubespray_checkout() (
    repository=$1
    destination=$2
    revision=$3
    if [ -z "$revision" ] || [ -L "$destination" ]; then
        echo "ERROR: a selected Kubespray revision and non-symlink destination are required" >&2
        return 1
    fi
    if [ -e "$destination" ]; then
        if [ ! -d "$destination/.git" ]; then
            echo "ERROR: existing Kubespray destination is not a Git checkout" >&2
            return 1
        fi
    else
        git clone --no-checkout -- "$repository" "$destination" || return "$?"
        git -C "$destination" checkout --detach "$revision" || return "$?"
    fi
    actual_repository=$(git -C "$destination" remote get-url origin) || return "$?"
    if [ "$actual_repository" != "$repository" ]; then
        echo "ERROR: Kubespray repository differs from the configured source" >&2
        return 1
    fi
    changes=$(git -C "$destination" status --porcelain=v1) || return "$?"
    if [ -n "$changes" ]; then
        echo "ERROR: Kubespray checkout has local changes; preserving it unchanged" >&2
        return 1
    fi
    expected=$(git -C "$destination" rev-parse --verify "$revision^{commit}") || return "$?"
    actual=$(git -C "$destination" rev-parse HEAD) || return "$?"
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: Kubespray checkout differs from the configured revision" >&2
        return 1
    fi
)

phase3_write_kube_version() {
    if [ -n "$1" ]; then
        # Kubespray adds v to download URLs itself; its comparisons use bare versions.
        printf 'kube_version: "%s"\n' "${1#v}"
    fi
}

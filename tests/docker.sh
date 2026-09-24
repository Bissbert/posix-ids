#!/bin/sh
# docker.sh - Run the test suite in Linux containers.
#
# The tests write system paths (/var/log/auth.log, /etc/ids, crontabs), so
# they only run inside containers; nothing here changes the host.
#
#   tests/regression/*.sh  one container each, Debian 12 (dash, mawk)
#   tests/static/*.py      Splunk and Ansible reference checks
#   tests/ansible/deploy.sh  syntax-check every playbook, deploy with site.yml
#
# Usage: sh tests/docker.sh [NAME...]   run only tests whose file name
#                                       contains one of NAME
# Exits 0 when every check passes.

set -u
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SHELL_IMAGE=posix-ids-test-shell
ANSIBLE_IMAGE=posix-ids-test-ansible
OUT=$(mktemp -d "${TMPDIR:-/tmp}/ids-tests.XXXXXX")
trap 'rm -rf "$OUT"' EXIT

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }

wanted() {
    [ $# -gt 1 ] || return 0
    name=$1
    shift
    for f in "$@"; do
        case $name in *"$f"*) return 0 ;; esac
    done
    return 1
}

echo "Building test images..."
docker build -q -t "$SHELL_IMAGE" -f "$REPO/tests/shell.Dockerfile" "$REPO/tests" >/dev/null || exit 2
docker build -q -t "$ANSIBLE_IMAGE" -f "$REPO/tests/ansible.Dockerfile" "$REPO/tests" >/dev/null || exit 2

failures=0
run() {
    image=$1 name=$2
    shift 2
    wanted "$name" ${FILTER:+$FILTER} || return 0
    printf '\n== %s\n' "$name"
    docker run --rm -v "$REPO:/src:ro" "$image" "$@" > "$OUT/$name.log" 2>&1
    rc=$?
    cat "$OUT/$name.log"
    if [ "$rc" -ne 0 ]; then
        failures=$((failures + 1))
        grep -q '^not ok' "$OUT/$name.log" || echo "not ok $name exited $rc"
    fi
}

FILTER="$*"
for t in "$REPO"/tests/regression/*.sh; do
    name=$(basename "$t" .sh)
    run "$SHELL_IMAGE" "$name" sh "/src/tests/regression/$name.sh"
done
for t in "$REPO"/tests/static/*.py; do
    name=$(basename "$t" .py)
    run "$ANSIBLE_IMAGE" "$name" python3 "/src/tests/static/$name.py"
done
run "$ANSIBLE_IMAGE" ansible_deploy sh /src/tests/ansible/deploy.sh

passed=$(cat "$OUT"/*.log 2>/dev/null | grep -c '^ok')
failed=$(cat "$OUT"/*.log 2>/dev/null | grep -c '^not ok')
printf '\n%s checks passed, %s failed\n' "$passed" "$failed"
[ "$failures" -eq 0 ] && [ "$failed" -eq 0 ]

#!/bin/sh
# lib.sh - Helpers shared by the regression tests in tests/regression.
#
# The tests write /var/log/auth.log, /var/lib/ids and the other paths the
# IDS reads, so they refuse to run outside a container. Use tests/docker.sh.
# Each assertion prints one "ok" or "not ok" line; finish exits 1 if any
# assertion failed.

export LC_ALL=C

if [ ! -f /.dockerenv ] && [ "${IDS_TEST_CONTAINER:-0}" != "1" ]; then
    echo "These tests change system paths. Run them with tests/docker.sh." >&2
    exit 2
fi

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN="$REPO/bin"
T_FAILED=0

ok() { printf 'ok     %s\n' "$*"; }
not_ok() { printf 'not ok %s\n' "$*"; T_FAILED=1; }
finish() { exit "$T_FAILED"; }

# check DESCRIPTION COMMAND... records whether COMMAND succeeds.
check() {
    desc=$1
    shift
    if "$@"; then ok "$desc"; else not_ok "$desc"; fi
}

# A private IDS_HOME with a copy of config/ids.conf pointing into it.
# Syslog output is off unless a test turns it on.
new_sandbox() {
    S=$(mktemp -d /tmp/ids-test.XXXXXX)
    sed -e "s|/var/log/ids|$S|g" -e 's/^ALERT_TO_SYSLOG=1/ALERT_TO_SYSLOG=0/' \
        "$REPO/config/ids.conf" > "$S/ids.conf"
    CONF="$S/ids.conf"
    ALERTS="$S/alerts.json"
}

# set_conf KEY VALUE replaces KEY in the sandbox configuration.
set_conf() {
    grep -v "^$1=" "$CONF" > "$CONF.new"
    printf '%s=%s\n' "$1" "$2" >> "$CONF.new"
    mv "$CONF.new" "$CONF"
}

# run_monitor runs one monitor pass and keeps its exit status in RC and its
# stderr in $S/monitor.err.
run_monitor() {
    RC=0
    sh "$BIN/monitor.sh" -c "$CONF" -1 > "$S/monitor.out" 2> "$S/monitor.err" || RC=$?
}

# has_alert TEXT: an alert record in this sandbox contains TEXT.
has_alert() { grep -q -- "$1" "$ALERTS" 2>/dev/null; }
no_alert() { ! has_alert "$1"; }

# syslog_stamp SECONDS_AGO prints a traditional syslog timestamp.
syslog_stamp() { date -d "@$(( $(date +%s) - $1 ))" '+%b %e %H:%M:%S'; }
# rfc3339_stamp SECONDS_AGO prints an rsyslog high-precision timestamp.
rfc3339_stamp() { date -d "@$(( $(date +%s) - $1 ))" '+%Y-%m-%dT%H:%M:%S.123456%:z'; }

# failed_passwords COUNT IP STAMP prints sshd failure lines.
failed_passwords() {
    i=0
    while [ "$i" -lt "$1" ]; do
        printf '%s host sshd[100]: Failed password for root from %s port 4%04d ssh2\n' "$3" "$2" "$i"
        i=$((i + 1))
    done
}

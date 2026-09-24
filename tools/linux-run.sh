#!/bin/sh
# linux-run.sh - Run every check in docs/measurement.md inside Linux containers.
#
#   sh tools/linux-run.sh > media/captures/linux-run.txt
#
# The repository is mounted read-only and copied. The installer, the test
# script and the baseline generator write system paths, so they only ever run
# inside a disposable debian:12-slim container. tools/container_run.sh then
# runs the monitor end to end in a second container.
#
# The regression suite is separate: sh tests/docker.sh

set -eu
IMAGE=debian:12-slim
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

docker pull -q "$IMAGE" >/dev/null

docker run --rm -i -v "$REPO:/src:ro" "$IMAGE" /bin/sh -s <<'INNER'
set -u
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
section() { printf '\n=== %s\n' "$*"; }

apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y git procps net-tools >/dev/null 2>&1
cp -r /src /ids && cd /ids
git config --global --add safe.directory /ids

section "environment"
. /etc/os-release; echo "$PRETTY_NAME, $(uname -srm)"
echo "/bin/sh -> $(readlink -f /bin/sh)"

section "tools/measure.sh"
sh tools/measure.sh

section "help output"
sh bin/monitor.sh -h >/dev/null; echo "bin/monitor.sh -h  exit=$?"
sh bin/alert.sh -h >/dev/null;   echo "bin/alert.sh -h    exit=$?"

section "bin/setup.sh -s (simulate)"
sh bin/setup.sh -s > /tmp/sim.out 2>&1; echo "exit=$?"
grep -E 'Would install|not found' /tmp/sim.out

section "bin/setup.sh (real install, as root, inside this container)"
sh bin/setup.sh > /tmp/setup.out 2>&1; echo "exit=$?"
grep -E '^\[(ERROR|WARN)\]|Installed:|Created init script|No service manager' /tmp/setup.out
ls -l /usr/local/bin/ids_monitor /usr/local/bin/ids_baseline /usr/local/bin/ids_alert /etc/ids/ids_config.conf | awk '{print $1, $NF}'

run_tests() {
    sh tests/test.sh -c /etc/ids/ids_config.conf > /tmp/test.out 2>&1; echo "exit=$?"
    printf 'last test started: %s\n' "$(grep -E '^\[TEST\] Test [0-9]+' /tmp/test.out | tail -1 | cut -c8-)"
    printf 'runtime [PASS] lines: %s\n' "$(grep -c '^\[PASS\]' /tmp/test.out)"
    printf 'runtime [FAIL] lines: %s\n' "$(grep -c '^\[FAIL\]' /tmp/test.out)"
    grep -E '^\[TEST\] (Tests run|Passed|Failed|Result)' /tmp/test.out || echo "(no summary printed)"
}

section "tests/test.sh after a fresh install (empty alerts.json)"
rm -f /var/log/ids/alerts.json
run_tests

section "tests/test.sh with one earlier record in alerts.json"
echo '{"severity":"low","category":"seed","description":"earlier record"}' > /var/log/ids/alerts.json
run_tests

section "baseline producer and monitor input"
grep -n '^BASELINE_FILE' /etc/ids/ids_config.conf
sh bin/baseline.sh -c /etc/ids/ids_config.conf -n; echo "baseline.sh -n  exit=$?"
printf '/var/log/ids/baseline.dat (monitor.sh reads): '
[ -f /var/log/ids/baseline.dat ] && echo "present, $(grep -vc "^#" /var/log/ids/baseline.dat) entries" || echo absent
sh bin/baseline.sh -c /etc/ids/ids_config.conf -V; echo "baseline.sh -V (unchanged)  exit=$?"

section "syslog priority built from an IDS severity"
sed -n '/^syslog_priority()/,/^}/p' bin/monitor.sh
for pri in auth.crit auth.err auth.warning auth.notice auth.info security.medium; do
    logger --no-act --socket-errors=off -p "$pri" test 2>/dev/null
    echo "logger -p $pri  exit=$?"
done
INNER

printf '\n=== tools/container_run.sh\n'
sh "$REPO/tools/container_run.sh" "$IMAGE"

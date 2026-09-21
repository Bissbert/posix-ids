#!/bin/sh
# container_run.sh - Run the IDS end-to-end inside a throwaway Linux container.
#
# The IDS only does anything interesting on Linux: it reads /proc, /var/log/auth.log
# and netstat output.  This script boots a Debian container, prepares the checked-in
# monitor with an isolated configuration and baseline, plants harmless artefacts,
# runs two passes, and prints the resulting alert records.
#
# Requires: docker and network access for the package install.  Everything else
# happens inside the container.
# Usage: tools/container_run.sh [IMAGE]        (default: debian:12-slim)

set -eu
IMAGE=${1:-debian:12-slim}
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }

exec docker run --rm -i -v "$REPO:/src:ro" "$IMAGE" /bin/sh -s <<'INNER'
set -eu
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

section() { printf '\n== %s ==\n' "$*"; }

section "container"
. /etc/os-release; echo "image      : $PRETTY_NAME"
echo "/bin/sh    : $(readlink -f /bin/sh)"
echo "kernel     : $(uname -sr)"

section "tools present in the base image (before installing anything)"
for t in awk sed grep find ps netstat ss sha256sum md5sum diff logger top df wc sort uniq tr; do
    printf '%-12s %s\n' "$t" "$(command -v "$t" >/dev/null 2>&1 && echo yes || echo NO)"
done

section "installing procps + net-tools"
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y procps net-tools >/dev/null 2>&1
echo "ps       -> $(command -v ps)"
echo "netstat  -> $(command -v netstat)"

# The repo is mounted read-only; copy it so all measurement inputs stay isolated.
cp -r /src /ids && cd /ids

section "preparing the checked-in monitor"
mkdir -p /var/log/ids/state /var/www /usr/local/bin /etc/ssh
printf 'Port 22\nPermitRootLogin no\n' > /etc/ssh/sshd_config
# The container has no syslog facility named "security.medium".  Disable that
# optional sink so an alert does not turn into a logger error during the run.
sed 's/^ALERT_TO_SYSLOG=1/ALERT_TO_SYSLOG=0/' \
    /src/config/ids.conf > /tmp/ids_config.conf

# monitor.sh expects a flat SHA-256 baseline at this path.  The checked-in
# baseline.sh creates a different directory-shaped MD5 baseline, so construct
# the exact input its file-integrity check consumes for this measurement.
: > /var/log/ids/baseline.dat
for file in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
    [ -f "$file" ] && sha256sum "$file" >> /var/log/ids/baseline.dat
done

section "monitor syntax"
sh -n /src/bin/monitor.sh
echo "monitor syntax: pass"

section "pass 1 (cold: no state files yet)"
sh /src/bin/monitor.sh -c /tmp/ids_config.conf -1 2>&1 | sed 's/^/  /'
echo "alerts after pass 1: $(wc -l < /var/log/ids/alerts.json)"

section "planting artefacts the checks are supposed to notice"
# 1. brute force + failed logins: 12 failed SSH passwords from one address
i=0; while [ $i -lt 12 ]; do
    printf 'Jan  1 00:00:%02d host sshd[100]: Failed password for root from 203.0.113.9 port 40000 ssh2\n' "$i"
    printf 'Jan  1 00:00:%02d host sshd[100]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.9\n' "$i"
    i=$((i + 1))
done > /var/log/auth.log
echo "  /var/log/auth.log         12 failed passwords from 203.0.113.9"

# 2. sudo anomaly: 15 sudo lines
i=0; while [ $i -lt 15 ]; do
    printf 'Jan  1 00:01:%02d host sudo:  root : COMMAND=/bin/ls\n' "$i"
    i=$((i + 1))
done >> /var/log/auth.log
echo "  /var/log/auth.log         15 sudo invocations"

# 3. webshell
mkdir -p /var/www/html
printf '<?php eval($_GET["c"]); ?>\n' > /var/www/html/uploads.php
echo "  /var/www/html/uploads.php eval() one-liner"

# 4. new SUID binary in a watched directory
cp /bin/true /usr/bin/backdoor && chmod 4755 /usr/bin/backdoor
echo "  /usr/bin/backdoor         mode 4755"

# 5. new user account
echo 'eviluser:x:1337:1337::/home/eviluser:/bin/sh' >> /etc/passwd
echo "  /etc/passwd               new account eviluser (uid 1337)"

# 6. cryptominer by process name
cp /bin/sleep /usr/local/bin/xmrig && /usr/local/bin/xmrig 300 &
echo "  /usr/local/bin/xmrig      running (a renamed sleep)"

# 7. process whose binary has been unlinked
cp /bin/sleep /tmp/ghost && /tmp/ghost 300 &
sleep 1; rm -f /tmp/ghost
echo "  /tmp/ghost                running, binary deleted"

# 8. changed sshd_config
printf 'Port 22\nPermitRootLogin yes\n' > /etc/ssh/sshd_config
echo "  /etc/ssh/sshd_config      PermitRootLogin yes"

# 9. changed cron
mkdir -p /etc/cron.d
printf '* * * * * root /tmp/implant\n' > /etc/cron.d/implant
echo "  /etc/cron.d/implant       new cron entry"

section "pass 2 (warm: state from pass 1 exists)"
: > /var/log/ids/alerts.json
start=$(date +%s%N 2>/dev/null || echo 0)
set +e
sh /src/bin/monitor.sh -c /tmp/ids_config.conf -1 > /tmp/pass2.out 2> /tmp/pass2.err
rc=$?
set -e
end=$(date +%s%N 2>/dev/null || echo 0)
echo "  monitor output:"
sed 's/^/    /' /tmp/pass2.out || true
echo "  monitor diagnostics:"
sed 's/^/    /' /tmp/pass2.err || true
echo "  monitor exit status: $rc"

section "alert records written by pass 2"
cat /var/log/ids/alerts.json

section "alerts by category and severity"
sed -n 's/.*"severity":"\([a-z]*\)","category":"\([a-z]*\)".*/\2 \1/p' \
    /var/log/ids/alerts.json | sort | uniq -c | sort -rn

section "resource cost of one pass"
if [ "$start" != 0 ]; then
    echo "  wall clock (ns diff)      : $((end - start))"
else
    echo "  wall clock                : not measured (date lacks nanoseconds)"
fi

section "runtime files used by the measurement"
ls -l /var/log/ids/ /var/log/ids/state/ 2>/dev/null | sed 's/^/  /'
echo "  baseline file monitor.sh looks for (/var/log/ids/baseline.dat):"
[ -f /var/log/ids/baseline.dat ] && echo "    present" || echo "    ABSENT"
echo "  baseline directory baseline.sh writes (/var/lib/ids/baseline):"
[ -d /var/lib/ids/baseline ] && echo "    present, $(find /var/lib/ids/baseline -type f | wc -l) files" || echo "    ABSENT"
INNER

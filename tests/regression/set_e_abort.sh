#!/bin/sh
# Regression test for #11: a below-threshold row at the end of the
# brute-force or port-scan tally must not end the run under set -e.
. "$(dirname "$0")/../lib.sh"

new_sandbox
sh "$BIN/baseline.sh" -c "$CONF" -n >/dev/null 2>&1

# 203.0.113.9 is over the threshold; 203.0.113.99 sorts after it with one line.
now=$(syslog_stamp 5)
{
    failed_passwords 8 203.0.113.9 "$now"
    failed_passwords 1 203.0.113.99 "$now"
} > /var/log/auth.log
run_monitor
check "brute force: monitor exits 0" [ "$RC" -eq 0 ]
check "brute force: the alert for the busy address is raised" has_alert '"IP: 203.0.113.9, Attempts: 8"'
check "brute force: the run reaches the last check" [ -s "$S/state/last_check.state" ]

# A netstat that reports 12 connections from one address and 1 from another.
: > /var/log/auth.log
: > "$ALERTS"
rm -f "$S/state/last_check.state"
mkdir -p "$S/shim"
cat > "$S/shim/netstat" <<'SHIM'
#!/bin/sh
echo "Active Internet connections (w/o servers)"
echo "Proto Recv-Q Send-Q Local Address           Foreign Address         State"
i=0
while [ $i -lt 12 ]; do
    echo "tcp        0      0 10.0.0.2:22             198.51.100.7:443        ESTABLISHED"
    i=$((i + 1))
done
echo "tcp        0      0 10.0.0.2:22             198.51.100.8:443        ESTABLISHED"
SHIM
chmod +x "$S/shim/netstat"
PATH="$S/shim:$PATH" run_monitor
check "port scan: monitor exits 0" [ "$RC" -eq 0 ]
check "port scan: the alert for the busy address is raised" has_alert '"IP: 198.51.100.7, Connections: 12"'
check "port scan: the run reaches the last check" [ -s "$S/state/last_check.state" ]

finish

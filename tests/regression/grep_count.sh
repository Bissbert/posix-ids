#!/bin/sh
# Regression test for #10: an auth log with no matching lines must not
# make the failed-login and sudo checks compare "0\n0" as a number.
. "$(dirname "$0")/../lib.sh"

new_sandbox
sh "$BIN/baseline.sh" -c "$CONF" -n >/dev/null 2>&1
printf '%s host CRON[1]: pam_unix(cron:session): session opened for user root\n' \
    "$(syslog_stamp 5)" > /var/log/auth.log

run_monitor
check "monitor exits 0" [ "$RC" -eq 0 ]
check "no shell error on stderr" sh -c "! grep -E 'Illegal number|integer expression|unexpected operator' '$S/monitor.err'"
check "no failed-login alert" no_alert "Excessive failed login attempts"
check "no sudo alert" no_alert "Unusual sudo activity"

finish

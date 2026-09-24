#!/bin/sh
# Regression test for #6: the brute-force, failed-login and sudo checks must
# count auth log entries inside their time windows, not the last N lines.
. "$(dirname "$0")/../lib.sh"

new_sandbox
sh "$BIN/baseline.sh" -c "$CONF" -n >/dev/null 2>&1

pam_failures() {
    i=0
    while [ "$i" -lt "$1" ]; do
        printf '%s host sshd[101]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s\n' "$3" "$2"
        i=$((i + 1))
    done
}
sudo_lines() {
    i=0
    while [ "$i" -lt "$1" ]; do
        printf '%s host sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls\n' "$2"
        i=$((i + 1))
    done
}

# Traditional syslog stamps. Two days old: outside every window.
old=$(syslog_stamp 172800)
{
    failed_passwords 12 203.0.113.9 "$old"
    pam_failures 12 203.0.113.9 "$old"
    sudo_lines 15 "$old"
} > /var/log/auth.log
run_monitor
check "old failed passwords raise no brute-force alert" no_alert "Brute force attack detected"
check "old PAM failures raise no failed-login alert" no_alert "Excessive failed login attempts"
check "old sudo lines raise no sudo alert" no_alert "Unusual sudo activity"

# Two hours old: outside the 5-minute auth window, outside the hour for sudo.
sudo_lines 15 "$(syslog_stamp 7200)" >> /var/log/auth.log
run_monitor
check "sudo lines two hours old raise no sudo alert" no_alert "Unusual sudo activity"

# Recent entries inside the windows.
now=$(syslog_stamp 10)
{
    failed_passwords 12 203.0.113.9 "$now"
    pam_failures 7 203.0.113.9 "$now"
    sudo_lines 11 "$(syslog_stamp 1800)"
} >> /var/log/auth.log
run_monitor
check "recent failed passwords raise a brute-force alert" has_alert '"IP: 203.0.113.9, Attempts: 12"'
check "recent PAM failures raise a failed-login alert" has_alert '"Count: 7"'
check "sudo lines from the last hour raise a sudo alert" has_alert '"Count: 11"'

# RFC 3339 stamps (rsyslog high-precision format) are read the same way.
: > "$ALERTS"
{
    failed_passwords 12 198.51.100.4 "$(rfc3339_stamp 172800)"
    failed_passwords 9 198.51.100.5 "$(rfc3339_stamp 20)"
} > /var/log/auth.log
run_monitor
check "old RFC 3339 lines raise no alert" no_alert "198.51.100.4"
check "recent RFC 3339 lines raise an alert" has_alert '"IP: 198.51.100.5, Attempts: 9"'

finish

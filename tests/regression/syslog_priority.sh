#!/bin/sh
# Regression test for #5: the syslog priority must be a valid
# facility.level, and a failed logger call must not end the monitor run.
. "$(dirname "$0")/../lib.sh"

REAL_LOGGER=$(command -v logger)
new_sandbox
set_conf ALERT_TO_SYSLOG 1
mkdir -p "$S/shim"
export LOGGER_CALLS="$S/logger.calls"

# A logger that parses its arguments with util-linux and records the result
# without needing a syslog daemon (no /dev/log in the container).
cat > "$S/shim/logger" <<SHIM
#!/bin/sh
rc=0
$REAL_LOGGER --no-act --socket-errors=off "\$@" 2>/dev/null || rc=\$?
printf '%s %s\n' "\$rc" "\$*" >> "\$LOGGER_CALLS"
exit \$rc
SHIM
chmod +x "$S/shim/logger"

# No baseline yet, so the run raises a high "Baseline file missing" alert.
PATH="$S/shim:$PATH" run_monitor
check "monitor called logger" [ -s "$LOGGER_CALLS" ]
check "every logger call used a priority logger accepts" \
    sh -c "! grep -v '^0 ' '$LOGGER_CALLS'"
check "a high alert goes to auth.err" grep -q -- '-p auth.err filesystem: Baseline file missing' "$LOGGER_CALLS"
check "monitor exits 0" [ "$RC" -eq 0 ]

# A logger that always fails: the alert must still reach the file and the
# remaining checks must still run.
printf '#!/bin/sh\nexit 1\n' > "$S/shim/logger"
: > "$ALERTS"
PATH="$S/shim:$PATH" run_monitor
check "monitor exits 0 when logger fails" [ "$RC" -eq 0 ]
check "the alert is still written to the alert log" has_alert "Baseline file missing"
check "the run reaches the last check" [ -s "$S/state/last_check.state" ]
check "the logger failure is reported" grep -q 'logger failed' "$S/monitor.err"

finish

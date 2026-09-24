#!/bin/sh
# ids_monitor.sh - Main IDS monitoring script
# Purpose: Continuous monitoring for intrusion detection
# Portable: POSIX sh (dash/ash/BusyBox compatible)
# Usage: ids_monitor.sh [-c CONFIG] [-d] [-1]

set -eu
export LC_ALL=C

CONFIG="/etc/ids/ids_config.conf"
DAEMON=0
ONESHOT=0

err() { printf '[ERROR] %s\n' "$*" >&2; }
info() { printf '[INFO] %s\n' "$*" >&2; }

usage() {
    cat <<'USAGE'
Usage: ids_monitor.sh [-c CONFIG] [-d] [-1]
  -c CONFIG   configuration file
  -d          run as daemon
  -1          run once and exit
  -h          show help
USAGE
}

while getopts ":c:d1h" opt; do
    case "$opt" in
        c) CONFIG=$OPTARG ;;
        d) DAEMON=1 ;;
        1) ONESHOT=1 ;;
        h) usage; exit 0 ;;
        \?) err "Unknown option: -$OPTARG"; usage; exit 2 ;;
        :) err "Missing argument for -$OPTARG"; usage; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

# Load configuration
if [ -f "$CONFIG" ]; then
    . "$CONFIG"
else
    err "Configuration file not found: $CONFIG"
    exit 1
fi

# Ensure log directory exists
[ -d "$IDS_HOME" ] || mkdir -p "$IDS_HOME"

# Time windows for the auth log checks, in seconds. Configurations written
# before these settings existed fall back to the documented defaults.
AUTH_WINDOW=${AUTH_WINDOW:-300}
SUDO_WINDOW=${SUDO_WINDOW:-3600}
AUTH_LOG_SCAN_LINES=${AUTH_LOG_SCAN_LINES:-50000}

# State files
STATE_DIR="$IDS_HOME/state"
[ -d "$STATE_DIR" ] || mkdir -p "$STATE_DIR"

PORT_SCAN_STATE="$STATE_DIR/port_scan.state"
BRUTE_FORCE_STATE="$STATE_DIR/brute_force.state"
LAST_CHECK_STATE="$STATE_DIR/last_check.state"

# Initialize state files
: > "$PORT_SCAN_STATE"
: > "$BRUTE_FORCE_STATE"
: > "$LAST_CHECK_STATE"

# JSON escape function
json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g; s/\n/\\n/g; s/\r/\\r/g'
}

# Log alert in JSON format
log_alert() {
    severity="$1"
    category="$2"
    description="$3"
    details="${4:-}"

    timestamp=$(date +%Y-%m-%dT%H:%M:%SZ)

    json_log=$(printf '{"timestamp":"%s","hostname":"%s","severity":"%s","category":"%s","description":"%s"' \
        "$timestamp" "$(json_escape "$HOSTNAME")" "$severity" "$category" "$(json_escape "$description")")

    if [ -n "$details" ]; then
        json_log="${json_log},\"details\":\"$(json_escape "$details")\""
    fi

    json_log="${json_log}}"

    # Output based on configuration
    if [ "$ALERT_TO_FILE" = "1" ]; then
        printf '%s\n' "$json_log" >> "$ALERT_LOG"
    fi

    if [ "$ALERT_TO_STDOUT" = "1" ]; then
        printf '%s\n' "$json_log"
    fi

    if [ "$ALERT_TO_SYSLOG" = "1" ] && command -v logger >/dev/null 2>&1; then
        # A failed syslog write must not stop the remaining checks.
        logger -t "ids" -p "$(syslog_priority "$severity")" "$category: $description" 2>/dev/null ||
            err "logger failed for $category alert"
    fi
}

# Map an IDS severity onto a syslog facility.level pair. syslog has no
# "high" or "medium" level, so the IDS names cannot be passed through.
syslog_priority() {
    case "$1" in
        critical) printf 'auth.crit' ;;
        high) printf 'auth.err' ;;
        medium) printf 'auth.warning' ;;
        low) printf 'auth.notice' ;;
        *) printf 'auth.info' ;;
    esac
}

# Rotate logs if needed
rotate_logs() {
    for log_file in "$ALERT_LOG" "$MONITOR_LOG"; do
        if [ -f "$log_file" ]; then
            size=$(wc -c < "$log_file" 2>/dev/null || printf "0")
            if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
                i=$MAX_LOG_FILES
                while [ "$i" -gt 0 ]; do
                    j=$((i - 1))
                    [ -f "${log_file}.$j" ] && mv "${log_file}.$j" "${log_file}.$i"
                    i=$j
                done
                mv "$log_file" "${log_file}.0"
                : > "$log_file"
                info "Rotated log: $log_file"
            fi
        fi
    done
}

# Network monitoring functions
check_port_scans() {
    if command -v netstat >/dev/null 2>&1; then
        netstat -tn 2>/dev/null | awk '/ESTABLISHED|SYN_RECV/ {print $5}' | \
            sed 's/:[^:]*$//' | sort | uniq -c | \
            while read -r count ip; do
                # An if keeps a below-threshold row from failing the pipeline under set -e.
                if [ "$count" -gt "$PORT_SCAN_THRESHOLD" ]; then
                    log_alert "$SEV_HIGH" "network" "Possible port scan detected" "IP: $ip, Connections: $count"
                fi
            done
    fi
}

# Print the auth log lines stamped within the last $1 seconds. Reads the
# traditional syslog stamp ("Sep 24 09:42:17", local time, no year) and the
# RFC 3339 stamp rsyslog writes with its high-precision template.
auth_log_recent() {
    window=$1
    auth_log=""
    for log in /var/log/auth.log /var/log/secure; do
        [ -f "$log" ] && auth_log="$log" && break
    done
    [ -n "$auth_log" ] || return 0

    tail -n "$AUTH_LOG_SCAN_LINES" "$auth_log" 2>/dev/null | awk \
        -v window="$window" \
        -v now_local="$(date '+%Y %m %d %H %M %S')" \
        -v now_utc="$(date -u '+%Y %m %d %H %M %S')" '
        # Days since 1970-01-01 in the proleptic Gregorian calendar.
        function days(y, m, d) {
            if (m <= 2) { y--; m += 12 }
            return 365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + d - 719469
        }
        function stamp(y, mo, d, h, mi, s) {
            return days(y + 0, mo + 0, d + 0) * 86400 + h * 3600 + mi * 60 + s
        }
        BEGIN {
            split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " ")
            for (i = 1; i <= 12; i++) mon[names[i]] = i
            split(now_local, a, " "); local_now = stamp(a[1], a[2], a[3], a[4], a[5], a[6]); year = a[1] + 0
            split(now_utc, b, " "); utc_now = stamp(b[1], b[2], b[3], b[4], b[5], b[6])
        }
        ($1 in mon) && $3 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ {
            split($3, t, ":")
            ts = stamp(year, mon[$1], $2, t[1], t[2], t[3])
            # No year in the stamp: a date ahead of now belongs to last year.
            if (ts > local_now + 86400) ts = stamp(year - 1, mon[$1], $2, t[1], t[2], t[3])
            if (local_now - ts <= window) print
            next
        }
        $1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/ {
            ts = stamp(substr($1, 1, 4), substr($1, 6, 2), substr($1, 9, 2), substr($1, 12, 2), substr($1, 15, 2), substr($1, 18, 2))
            zone = substr($1, 20); sub(/^[.][0-9]+/, "", zone); gsub(":", "", zone)
            now = local_now
            if (zone == "Z") now = utc_now
            else if (zone ~ /^[+-][0-9][0-9][0-9][0-9]$/) {
                off = substr(zone, 2, 2) * 3600 + substr(zone, 4, 2) * 60
                ts = (substr(zone, 1, 1) == "+") ? ts - off : ts + off
                now = utc_now
            }
            if (now - ts <= window) print
        }'
}

check_brute_force() {
    auth_log_recent "$AUTH_WINDOW" | \
        grep -E 'Failed password|authentication failure' | \
        sed -n 's/.*from \([0-9.]*\).*/\1/p' | \
        sort | uniq -c | \
        while read -r count ip; do
            if [ "$count" -gt "$BRUTE_FORCE_THRESHOLD" ]; then
                log_alert "$SEV_CRITICAL" "authentication" "Brute force attack detected" "IP: $ip, Attempts: $count"
            fi
        done
}

check_suspicious_connections() {
    if command -v netstat >/dev/null 2>&1; then
        netstat -tn 2>/dev/null | awk '/ESTABLISHED/ {print $5}' | \
            sed 's/.*://' | \
            while read -r port; do
                case ",$OUTBOUND_PORT_WHITELIST," in
                    *",$port,"*) ;;
                    *)
                        if [ -n "$port" ] && [ "$port" -gt 1024 ]; then
                            log_alert "$SEV_MEDIUM" "network" "Unusual outbound connection" "Port: $port"
                        fi
                        ;;
                esac
            done
    fi
}

# File system monitoring
check_file_integrity() {
    if [ ! -f "$BASELINE_FILE" ]; then
        log_alert "$SEV_HIGH" "filesystem" "Baseline file missing" "Run ids_baseline -c $CONFIG"
        return
    fi

    for file in $CRITICAL_FILES; do
        if [ -f "$file" ]; then
            current_sum=""
            baseline_sum=""

            if command -v sha256sum >/dev/null 2>&1; then
                current_sum=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
                baseline_sum=$(grep "^[a-f0-9]* *$file\$" "$BASELINE_FILE" 2>/dev/null | awk '{print $1}')
            elif command -v md5sum >/dev/null 2>&1; then
                current_sum=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
                baseline_sum=$(grep "MD5:.*$file\$" "$BASELINE_FILE" 2>/dev/null | sed 's/MD5://' | awk '{print $1}')
            fi

            if [ -n "$current_sum" ] && [ -n "$baseline_sum" ]; then
                if [ "$current_sum" != "$baseline_sum" ]; then
                    log_alert "$SEV_CRITICAL" "filesystem" "Critical file modified" "File: $file"
                fi
            fi
        fi
    done
}

check_suid_changes() {
    tmp_suid="${STATE_DIR}/suid_current.tmp"

    for dir in $CRITICAL_DIRS; do
        if [ -d "$dir" ]; then
            find "$dir" -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null
        fi
    done | awk '{print $NF":"$1}' | sort > "$tmp_suid"

    if [ -f "${STATE_DIR}/suid_last.state" ]; then
        diff "${STATE_DIR}/suid_last.state" "$tmp_suid" 2>/dev/null | \
            grep '^>' | sed 's/^> //' | \
            while IFS=: read -r file perms; do
                log_alert "$SEV_HIGH" "filesystem" "New SUID/SGID file detected" "File: $file, Perms: $perms"
            done
    fi

    mv "$tmp_suid" "${STATE_DIR}/suid_last.state"
}

check_webshells() {
    for web_dir in $WEB_DIRS; do
        if [ -d "$web_dir" ]; then
            # Look for suspicious PHP patterns
            find "$web_dir" -name "*.php" -type f -exec grep -l -E 'eval\(|base64_decode\(|system\(|exec\(|shell_exec\(|passthru\(|`.*`' {} \; 2>/dev/null | \
                while read -r file; do
                    log_alert "$SEV_CRITICAL" "filesystem" "Potential webshell detected" "File: $file"
                done
        fi
    done
}

# Authentication monitoring
check_new_users() {
    current_users="${STATE_DIR}/users_current.tmp"
    awk -F: '{print $1":"$3}' /etc/passwd | sort > "$current_users"

    if [ -f "${STATE_DIR}/users_last.state" ]; then
        diff "${STATE_DIR}/users_last.state" "$current_users" 2>/dev/null | \
            grep '^>' | sed 's/^> //' | \
            while IFS=: read -r user uid; do
                log_alert "$SEV_HIGH" "authentication" "New user created" "User: $user, UID: $uid"
            done
    fi

    mv "$current_users" "${STATE_DIR}/users_last.state"
}

check_failed_logins() {
    # grep -c prints 0 itself when nothing matches; only its status is ignored.
    recent_fails=$(auth_log_recent "$AUTH_WINDOW" | grep -c 'authentication failure' || true)

    if [ "$recent_fails" -gt "$MAX_FAILED_LOGINS" ]; then
        log_alert "$SEV_HIGH" "authentication" "Excessive failed login attempts" "Count: $recent_fails"
    fi
}

check_sudo_usage() {
    sudo_count=$(auth_log_recent "$SUDO_WINDOW" | grep -c 'sudo:' || true)

    if [ "$sudo_count" -gt "$SUDO_ANOMALY_THRESHOLD" ]; then
        log_alert "$SEV_MEDIUM" "authentication" "Unusual sudo activity" "Count: $sudo_count"
    fi
}

# Process monitoring
check_cryptominers() {
    ps aux 2>/dev/null | \
        grep -E "$MINER_PATTERNS" | \
        grep -v grep | \
        while read -r line; do
            proc=$(printf '%s' "$line" | awk '{print $11}')
            pid=$(printf '%s' "$line" | awk '{print $2}')
            log_alert "$SEV_CRITICAL" "process" "Potential cryptominer detected" "Process: $proc, PID: $pid"
        done
}

check_hidden_processes() {
    if [ -d /proc ]; then
        # Get PIDs from ps
        ps_pids="${STATE_DIR}/ps_pids.tmp"
        ps aux 2>/dev/null | awk 'NR>1 {print $2}' | sort -n > "$ps_pids"

        # Get PIDs from /proc
        proc_pids="${STATE_DIR}/proc_pids.tmp"
        ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n > "$proc_pids"

        # Find hidden processes (in /proc but not in ps)
        diff "$ps_pids" "$proc_pids" 2>/dev/null | \
            grep '^>' | sed 's/^> //' | \
            while read -r pid; do
                if [ -r "/proc/$pid/cmdline" ]; then
                    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 100)
                    log_alert "$SEV_HIGH" "process" "Hidden process detected" "PID: $pid, CMD: $cmd"
                fi
            done

        rm -f "$ps_pids" "$proc_pids"
    fi
}

check_deleted_binaries() {
    if [ -d /proc ]; then
        for pid_dir in /proc/[0-9]*; do
            [ -d "$pid_dir" ] || continue
            pid=$(basename "$pid_dir")

            if [ -r "$pid_dir/exe" ]; then
                exe_link=$(readlink "$pid_dir/exe" 2>/dev/null || :)
                case "$exe_link" in
                    *"(deleted)")
                        cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 50)
                        log_alert "$SEV_HIGH" "process" "Process running deleted binary" "PID: $pid, CMD: $cmd"
                        ;;
                esac
            fi
        done
    fi
}

# System resource monitoring
check_resource_usage() {
    # CPU usage
    if command -v top >/dev/null 2>&1; then
        cpu_idle=$(top -b -n 1 2>/dev/null | grep -E '^(%Cpu|CPU)' | \
            sed 's/.*\([0-9][0-9]*\.[0-9]\).*id.*/\1/' | head -1)

        if [ -n "$cpu_idle" ]; then
            cpu_used=$(awk "BEGIN {printf \"%.0f\", 100 - $cpu_idle}")
            if [ "$cpu_used" -gt "$CPU_THRESHOLD" ]; then
                log_alert "$SEV_MEDIUM" "resources" "High CPU usage" "Usage: ${cpu_used}%"
            fi
        fi
    fi

    # Memory usage
    if [ -f /proc/meminfo ]; then
        mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
        mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)

        if [ -n "$mem_total" ] && [ -n "$mem_avail" ] && [ "$mem_total" -gt 0 ]; then
            mem_used=$(awk "BEGIN {printf \"%.0f\", 100 - ($mem_avail * 100 / $mem_total)}")
            if [ "$mem_used" -gt "$MEM_THRESHOLD" ]; then
                log_alert "$SEV_MEDIUM" "resources" "High memory usage" "Usage: ${mem_used}%"
            fi
        fi
    fi

    # Disk usage
    df -h 2>/dev/null | awk 'NR>1 && $5~/[0-9]/ {gsub(/%/,"",$5); if ($5 > '"$DISK_THRESHOLD"') print $6":"$5}' | \
        while IFS=: read -r mount usage; do
            log_alert "$SEV_MEDIUM" "resources" "High disk usage" "Mount: $mount, Usage: ${usage}%"
        done

    # Process count
    proc_count=$(ps aux 2>/dev/null | wc -l)
    if [ "$proc_count" -gt "$PROC_COUNT_THRESHOLD" ]; then
        log_alert "$SEV_HIGH" "resources" "Excessive process count" "Count: $proc_count (possible fork bomb)"
    fi
}

# Configuration monitoring
check_ssh_config() {
    if [ -f /etc/ssh/sshd_config ]; then
        current_ssh="${STATE_DIR}/ssh_current.tmp"
        grep -E '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' \
            /etc/ssh/sshd_config 2>/dev/null | sort > "$current_ssh"

        if [ -f "${STATE_DIR}/ssh_last.state" ]; then
            if ! diff -q "${STATE_DIR}/ssh_last.state" "$current_ssh" >/dev/null 2>&1; then
                log_alert "$SEV_HIGH" "configuration" "SSH configuration changed" "/etc/ssh/sshd_config modified"
            fi
        fi

        mv "$current_ssh" "${STATE_DIR}/ssh_last.state"
    fi
}

check_cron_changes() {
    current_cron="${STATE_DIR}/cron_current.tmp"

    {
        for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly; do
            [ -d "$cron_dir" ] && ls -la "$cron_dir" 2>/dev/null
        done
        [ -f /etc/crontab ] && cat /etc/crontab 2>/dev/null
    } | sort > "$current_cron"

    if [ -f "${STATE_DIR}/cron_last.state" ]; then
        if ! diff -q "${STATE_DIR}/cron_last.state" "$current_cron" >/dev/null 2>&1; then
            log_alert "$SEV_HIGH" "configuration" "Cron configuration changed" "New or modified cron jobs detected"
        fi
    fi

    mv "$current_cron" "${STATE_DIR}/cron_last.state"
}

check_new_services() {
    current_services="${STATE_DIR}/services_current.tmp"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running 2>/dev/null | \
            awk '{print $1}' | grep '\.service$' | sort > "$current_services"
    elif command -v service >/dev/null 2>&1; then
        service --status-all 2>/dev/null | grep '\[ + \]' | awk '{print $NF}' | sort > "$current_services"
    else
        ps aux 2>/dev/null | awk '$11 !~ /^\[/ && NR>1 {print $11}' | \
            sed 's|.*/||' | sort -u > "$current_services"
    fi

    if [ -f "${STATE_DIR}/services_last.state" ]; then
        diff "${STATE_DIR}/services_last.state" "$current_services" 2>/dev/null | \
            grep '^>' | sed 's/^> //' | \
            while read -r service; do
                log_alert "$SEV_MEDIUM" "configuration" "New service detected" "Service: $service"
            done
    fi

    mv "$current_services" "${STATE_DIR}/services_last.state"
}

# Main monitoring function
run_checks() {
    info "Running security checks..."

    # Rotate logs if needed
    rotate_logs

    # Network checks
    check_port_scans
    check_brute_force
    check_suspicious_connections

    # File system checks
    check_file_integrity
    check_suid_changes
    check_webshells

    # Authentication checks
    check_new_users
    check_failed_logins
    check_sudo_usage

    # Process checks
    check_cryptominers
    check_hidden_processes
    check_deleted_binaries

    # Resource checks
    check_resource_usage

    # Configuration checks
    check_ssh_config
    check_cron_changes
    check_new_services

    # Update last check time
    date +%s > "$LAST_CHECK_STATE"
}

# Daemon mode
if [ "$DAEMON" = "1" ]; then
    info "Starting IDS monitor in daemon mode"
    info "PID: $$"
    printf '%d\n' $$ > "$IDS_HOME/ids_monitor.pid"

    trap 'info "Shutting down IDS monitor"; rm -f "$IDS_HOME/ids_monitor.pid"; exit 0' HUP INT TERM

    while true; do
        run_checks
        sleep "$CHECK_INTERVAL"
    done
elif [ "$ONESHOT" = "1" ]; then
    info "Running single check"
    run_checks
else
    # Interactive mode
    info "Starting IDS monitor in interactive mode"
    trap 'info "Stopped"; exit 0' HUP INT TERM

    while true; do
        run_checks
        info "Sleeping for $CHECK_INTERVAL seconds (Ctrl+C to stop)..."
        sleep "$CHECK_INTERVAL"
    done
fi
#!/bin/sh
# ids_alert.sh - Real-time alert handler for IDS
# Purpose: Process and route IDS alerts to various destinations
# Portable: POSIX sh (dash/ash/BusyBox compatible)
# Usage: ids_alert.sh [-c CONFIG] [-w WEBHOOK] [-e EMAIL] [-s SOCKET]

set -eu
export LC_ALL=C

CONFIG="/etc/ids/ids_config.conf"
WEBHOOK_URL=""
EMAIL_TO=""
SYSLOG_SOCKET=""
TAIL_MODE=0
ALERT_LOG="/var/log/ids/alerts.json"

err() { printf '[ERROR] %s\n' "$*" >&2; }
info() { printf '[INFO] %s\n' "$*" >&2; }

usage() {
    cat <<'USAGE'
Usage: ids_alert.sh [-c CONFIG] [-w WEBHOOK] [-e EMAIL] [-s SOCKET] [-t]
  -c CONFIG   configuration file
  -w WEBHOOK  webhook URL for alerts (Slack, Teams, etc)
  -e EMAIL    email address for critical alerts
  -s SOCKET   syslog socket path or TCP endpoint (host:port)
  -t          tail mode - follow log file in real-time
  -h          show help

Examples:
  # Send to webhook
  ids_alert.sh -w https://hooks.slack.com/services/XXX

  # Send to syslog TCP
  ids_alert.sh -s syslog.example.com:514

  # Email critical alerts
  ids_alert.sh -e security@example.com

  # Real-time monitoring
  ids_alert.sh -t -w https://webhook.url
USAGE
}

while getopts ":c:w:e:s:th" opt; do
    case "$opt" in
        c) CONFIG=$OPTARG ;;
        w) WEBHOOK_URL=$OPTARG ;;
        e) EMAIL_TO=$OPTARG ;;
        s) SYSLOG_SOCKET=$OPTARG ;;
        t) TAIL_MODE=1 ;;
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

# JSON field extraction (portable)
json_get() {
    json="$1"
    field="$2"

    # Extract field value from JSON
    printf '%s' "$json" | \
        sed -n 's/.*"'"$field"'":"\([^"]*\)".*/\1/p'
}

# Send to webhook (requires curl or wget)
send_webhook() {
    alert_json="$1"

    if [ -z "$WEBHOOK_URL" ]; then
        return 1
    fi

    # Format for common webhook services
    severity=$(json_get "$alert_json" "severity")
    category=$(json_get "$alert_json" "category")
    description=$(json_get "$alert_json" "description")
    hostname=$(json_get "$alert_json" "hostname")
    timestamp=$(json_get "$alert_json" "timestamp")

    # Slack-compatible format
    webhook_payload=$(cat <<EOF
{
  "text": "IDS Alert - $severity",
  "attachments": [{
    "color": "$([ "$severity" = "critical" ] && printf "danger" || printf "warning")",
    "title": "$category",
    "text": "$description",
    "fields": [
      {"title": "Hostname", "value": "$hostname", "short": true},
      {"title": "Time", "value": "$timestamp", "short": true}
    ]
  }]
}
EOF
    )

    # Try curl first, then wget
    if command -v curl >/dev/null 2>&1; then
        curl -X POST -H "Content-Type: application/json" \
            -d "$webhook_payload" "$WEBHOOK_URL" >/dev/null 2>&1 || \
            err "Failed to send webhook"
    elif command -v wget >/dev/null 2>&1; then
        printf '%s' "$webhook_payload" | \
            wget -q -O /dev/null --post-data=- \
                --header="Content-Type: application/json" \
                "$WEBHOOK_URL" || \
            err "Failed to send webhook"
    else
        err "Neither curl nor wget available for webhook"
        return 1
    fi
}

# Send email alert
send_email() {
    alert_json="$1"

    if [ -z "$EMAIL_TO" ]; then
        return 1
    fi

    severity=$(json_get "$alert_json" "severity")

    # Only email critical and high severity
    case "$severity" in
        critical|high)
            ;;
        *)
            return 0
            ;;
    esac

    category=$(json_get "$alert_json" "category")
    description=$(json_get "$alert_json" "description")
    hostname=$(json_get "$alert_json" "hostname")
    timestamp=$(json_get "$alert_json" "timestamp")

    subject="[IDS Alert] $severity - $category on $hostname"
    body="IDS Security Alert

Severity: $severity
Category: $category
Host: $hostname
Time: $timestamp

Description:
$description

Full Alert:
$alert_json"

    # Try different mail commands
    if command -v mail >/dev/null 2>&1; then
        printf '%s\n' "$body" | mail -s "$subject" "$EMAIL_TO"
    elif command -v sendmail >/dev/null 2>&1; then
        {
            printf 'To: %s\n' "$EMAIL_TO"
            printf 'Subject: %s\n' "$subject"
            printf '\n%s\n' "$body"
        } | sendmail "$EMAIL_TO"
    elif command -v mailx >/dev/null 2>&1; then
        printf '%s\n' "$body" | mailx -s "$subject" "$EMAIL_TO"
    else
        err "No mail command available"
        return 1
    fi
}

# Send to syslog
send_syslog() {
    alert_json="$1"

    if [ -z "$SYSLOG_SOCKET" ]; then
        return 1
    fi

    severity=$(json_get "$alert_json" "severity")
    category=$(json_get "$alert_json" "category")
    description=$(json_get "$alert_json" "description")

    # Map severity to syslog priority
    case "$severity" in
        critical) priority="auth.crit" ;;
        high)     priority="auth.err" ;;
        medium)   priority="auth.warning" ;;
        low)      priority="auth.notice" ;;
        *)        priority="auth.info" ;;
    esac

    # Check if it's a TCP endpoint or local socket
    case "$SYSLOG_SOCKET" in
        *:*)
            # TCP syslog (requires nc or telnet)
            host="${SYSLOG_SOCKET%:*}"
            port="${SYSLOG_SOCKET#*:}"

            syslog_msg="<134>$(date +"%b %d %H:%M:%S") $HOSTNAME ids[$]: $category - $description"

            if command -v nc >/dev/null 2>&1; then
                printf '%s\n' "$syslog_msg" | nc -w 1 "$host" "$port" 2>/dev/null
            elif command -v telnet >/dev/null 2>&1; then
                {
                    printf '%s\n' "$syslog_msg"
                    sleep 1
                    printf '\035\n'  # Ctrl+]
                    printf 'quit\n'
                } | telnet "$host" "$port" 2>/dev/null
            fi
            ;;
        *)
            # Local syslog
            if command -v logger >/dev/null 2>&1; then
                logger -t "ids" -p "$priority" "$category - $description"
            fi
            ;;
    esac
}

# Process alert
process_alert() {
    alert_json="$1"

    # Validate JSON structure
    if ! printf '%s' "$alert_json" | grep -q '"severity"'; then
        return 1
    fi

    # Send to configured destinations
    send_webhook "$alert_json" &
    send_email "$alert_json" &
    send_syslog "$alert_json" &

    # Wait for background jobs
    wait

    # Console output for debugging
    if [ -t 1 ]; then
        severity=$(json_get "$alert_json" "severity")
        category=$(json_get "$alert_json" "category")
        description=$(json_get "$alert_json" "description")

        # Color codes for terminal
        case "$severity" in
            critical) color="31" ;;  # Red
            high)     color="33" ;;  # Yellow
            medium)   color="36" ;;  # Cyan
            *)        color="37" ;;  # White
        esac

        printf '\033[%sm[%s] %s: %s\033[0m\n' "$color" "$severity" "$category" "$description"
    fi
}

# Tail mode - follow log file
tail_alerts() {
    if [ ! -f "$ALERT_LOG" ]; then
        err "Alert log not found: $ALERT_LOG"
        exit 1
    fi

    info "Following alerts from: $ALERT_LOG"
    info "Press Ctrl+C to stop"

    # Use tail -f to follow the log
    tail -f "$ALERT_LOG" 2>/dev/null | \
        while IFS= read -r line; do
            # Skip empty lines and non-JSON
            case "$line" in
                "{"*"}")
                    process_alert "$line"
                    ;;
            esac
        done
}

# Batch process recent alerts
process_recent() {
    if [ ! -f "$ALERT_LOG" ]; then
        err "Alert log not found: $ALERT_LOG"
        exit 1
    fi

    # Process last 100 alerts
    tail -100 "$ALERT_LOG" 2>/dev/null | \
        while IFS= read -r line; do
            case "$line" in
                "{"*"}")
                    process_alert "$line"
                    ;;
            esac
        done
}

# Main execution
if [ "$TAIL_MODE" = "1" ]; then
    tail_alerts
else
    # Process recent alerts once
    process_recent
fi
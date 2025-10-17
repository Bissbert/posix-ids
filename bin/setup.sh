#!/bin/sh
# setup_ids.sh - Installation and setup script for IDS
# Purpose: Install and configure the intrusion detection system
# Portable: POSIX sh (dash/ash/BusyBox compatible)
# Usage: setup_ids.sh [-p PREFIX] [-u USER] [-g GROUP]

set -eu
export LC_ALL=C

PREFIX="/usr/local"
IDS_USER="root"
IDS_GROUP="root"
CONFIG_DIR="/etc/ids"
SIMULATE=0

err() { printf '[ERROR] %s\n' "$*" >&2; }
info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }

usage() {
    cat <<'USAGE'
Usage: setup_ids.sh [-p PREFIX] [-u USER] [-g GROUP] [-s]
  -p PREFIX   installation prefix (default: /usr/local)
  -u USER     user to run IDS as (default: root)
  -g GROUP    group for IDS files (default: root)
  -s          simulate only (dry run)
  -h          show help

This script will:
  1. Create necessary directories
  2. Install IDS scripts to PREFIX/bin
  3. Setup configuration in /etc/ids
  4. Create systemd/init.d service (if applicable)
  5. Generate initial baseline
USAGE
}

while getopts ":p:u:g:sh" opt; do
    case "$opt" in
        p) PREFIX=$OPTARG ;;
        u) IDS_USER=$OPTARG ;;
        g) IDS_GROUP=$OPTARG ;;
        s) SIMULATE=1 ;;
        h) usage; exit 0 ;;
        \?) err "Unknown option: -$OPTARG"; usage; exit 2 ;;
        :) err "Missing argument for -$OPTARG"; usage; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

# Check if running as root (required for system-wide installation)
if [ "$(id -u)" != "0" ] && [ "$SIMULATE" = "0" ]; then
    err "This script must be run as root for system-wide installation"
    err "Use -s flag for simulation mode"
    exit 1
fi

info "IDS Installation Setup"
info "====================="
info "Prefix: $PREFIX"
info "User: $IDS_USER"
info "Group: $IDS_GROUP"
info "Config: $CONFIG_DIR"
[ "$SIMULATE" = "1" ] && info "Mode: SIMULATION (no changes will be made)"

# Verify user exists
if ! id "$IDS_USER" >/dev/null 2>&1; then
    err "User '$IDS_USER' does not exist"
    exit 1
fi

# Create directories
create_directory() {
    dir="$1"
    perms="$2"

    if [ "$SIMULATE" = "1" ]; then
        info "[SIMULATE] Would create: $dir (perms: $perms)"
    else
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            chmod "$perms" "$dir"
            chown "${IDS_USER}:${IDS_GROUP}" "$dir"
            info "Created: $dir"
        else
            info "Exists: $dir"
        fi
    fi
}

info ""
info "Creating directories..."
create_directory "$PREFIX/bin" 755
create_directory "$CONFIG_DIR" 750
create_directory "/var/log/ids" 750
create_directory "/var/log/ids/state" 750

# Install scripts
install_script() {
    src="$1"
    dst="$2"
    perms="$3"

    if [ ! -f "$src" ]; then
        warn "Source file not found: $src"
        return 1
    fi

    if [ "$SIMULATE" = "1" ]; then
        info "[SIMULATE] Would install: $src -> $dst (perms: $perms)"
    else
        cp "$src" "$dst"
        chmod "$perms" "$dst"
        chown "${IDS_USER}:${IDS_GROUP}" "$dst"
        info "Installed: $dst"
    fi
}

info ""
info "Installing IDS scripts..."
script_dir=$(dirname "$0")
install_script "$script_dir/ids_monitor.sh" "$PREFIX/bin/ids_monitor" 755
install_script "$script_dir/generate_baseline.sh" "$PREFIX/bin/ids_baseline" 755
install_script "$script_dir/ids_alert.sh" "$PREFIX/bin/ids_alert" 755

# Install configuration
info ""
info "Installing configuration..."
if [ "$SIMULATE" = "1" ]; then
    info "[SIMULATE] Would install: ids_config.conf -> $CONFIG_DIR/ids_config.conf"
else
    if [ -f "$CONFIG_DIR/ids_config.conf" ]; then
        info "Backing up existing configuration to $CONFIG_DIR/ids_config.conf.bak"
        cp "$CONFIG_DIR/ids_config.conf" "$CONFIG_DIR/ids_config.conf.bak"
    fi

    # Update paths in configuration
    sed "s|/var/log/ids|/var/log/ids|g" "$script_dir/ids_config.conf" > "$CONFIG_DIR/ids_config.conf"
    chmod 640 "$CONFIG_DIR/ids_config.conf"
    chown "${IDS_USER}:${IDS_GROUP}" "$CONFIG_DIR/ids_config.conf"
    info "Installed: $CONFIG_DIR/ids_config.conf"
fi

# Create systemd service if systemd is available
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    info ""
    info "Creating systemd service..."

    service_file="/etc/systemd/system/ids-monitor.service"
    service_content="[Unit]
Description=POSIX IDS Monitor
After=network.target

[Service]
Type=simple
User=$IDS_USER
Group=$IDS_GROUP
ExecStart=$PREFIX/bin/ids_monitor -c $CONFIG_DIR/ids_config.conf -d
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target"

    if [ "$SIMULATE" = "1" ]; then
        info "[SIMULATE] Would create systemd service: $service_file"
    else
        printf '%s\n' "$service_content" > "$service_file"
        systemctl daemon-reload
        info "Created systemd service: ids-monitor.service"
        info "To enable: systemctl enable ids-monitor"
        info "To start: systemctl start ids-monitor"
    fi

# Create init.d script for SysV init systems
elif [ -d /etc/init.d ]; then
    info ""
    info "Creating init.d service..."

    init_script="/etc/init.d/ids-monitor"
    init_content='#!/bin/sh
# IDS Monitor init script
# chkconfig: 2345 90 10
# description: POSIX IDS Monitor

### BEGIN INIT INFO
# Provides:          ids-monitor
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: POSIX IDS Monitor
# Description:       Intrusion Detection System Monitor
### END INIT INFO

DAEMON="'"$PREFIX"'/bin/ids_monitor"
PIDFILE="/var/run/ids-monitor.pid"
CONFIG="'"$CONFIG_DIR"'/ids_config.conf"

case "$1" in
    start)
        echo "Starting IDS Monitor..."
        $DAEMON -c $CONFIG -d &
        echo $! > $PIDFILE
        ;;
    stop)
        echo "Stopping IDS Monitor..."
        if [ -f $PIDFILE ]; then
            kill $(cat $PIDFILE)
            rm -f $PIDFILE
        fi
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        if [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE) 2>/dev/null; then
            echo "IDS Monitor is running (PID: $(cat $PIDFILE))"
        else
            echo "IDS Monitor is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac'

    if [ "$SIMULATE" = "1" ]; then
        info "[SIMULATE] Would create init script: $init_script"
    else
        printf '%s\n' "$init_content" > "$init_script"
        chmod 755 "$init_script"
        info "Created init script: $init_script"
        info "To enable: update-rc.d ids-monitor defaults (Debian/Ubuntu)"
        info "         or: chkconfig ids-monitor on (RHEL/CentOS)"
    fi
else
    info ""
    info "No service manager detected. Manual startup required:"
    info "  $PREFIX/bin/ids_monitor -c $CONFIG_DIR/ids_config.conf -d"
fi

# Create cron job for baseline updates
info ""
info "Setting up cron job for baseline updates..."
cron_file="/etc/cron.d/ids-baseline"
cron_content="# IDS Baseline Generation - Daily at 2 AM
0 2 * * * $IDS_USER $PREFIX/bin/ids_baseline -c $CONFIG_DIR/ids_config.conf >/dev/null 2>&1"

if [ "$SIMULATE" = "1" ]; then
    info "[SIMULATE] Would create cron job: $cron_file"
else
    if [ -d /etc/cron.d ]; then
        printf '%s\n' "$cron_content" > "$cron_file"
        chmod 644 "$cron_file"
        info "Created cron job: $cron_file"
    else
        info "No /etc/cron.d directory found. Add to crontab manually:"
        info "  $cron_content"
    fi
fi

# Generate initial baseline
info ""
info "Generating initial baseline..."
if [ "$SIMULATE" = "1" ]; then
    info "[SIMULATE] Would generate baseline: /var/log/ids/baseline.dat"
else
    "$PREFIX/bin/ids_baseline" -c "$CONFIG_DIR/ids_config.conf"
fi

# Create log rotation configuration
if [ -d /etc/logrotate.d ]; then
    info ""
    info "Setting up log rotation..."

    logrotate_file="/etc/logrotate.d/ids"
    logrotate_content="/var/log/ids/*.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 $IDS_USER $IDS_GROUP
    sharedscripts
    postrotate
        if [ -f /var/run/ids-monitor.pid ]; then
            kill -HUP \$(cat /var/run/ids-monitor.pid) 2>/dev/null || true
        fi
    endscript
}"

    if [ "$SIMULATE" = "1" ]; then
        info "[SIMULATE] Would create logrotate config: $logrotate_file"
    else
        printf '%s\n' "$logrotate_content" > "$logrotate_file"
        chmod 644 "$logrotate_file"
        info "Created logrotate config: $logrotate_file"
    fi
fi

# Summary
info ""
info "Installation Complete!"
info "====================="
info ""
info "Next steps:"
info "1. Review configuration: $CONFIG_DIR/ids_config.conf"
info "2. Test monitoring: $PREFIX/bin/ids_monitor -c $CONFIG_DIR/ids_config.conf -1"
info "3. View alerts: tail -f /var/log/ids/alerts.json"

if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    info "4. Enable service: systemctl enable ids-monitor"
    info "5. Start service: systemctl start ids-monitor"
elif [ -d /etc/init.d ]; then
    info "4. Enable service: update-rc.d ids-monitor defaults"
    info "5. Start service: /etc/init.d/ids-monitor start"
else
    info "4. Start manually: $PREFIX/bin/ids_monitor -c $CONFIG_DIR/ids_config.conf -d"
fi

info ""
info "Documentation:"
info "- Logs: /var/log/ids/alerts.json (Splunk-ready JSON)"
info "- State: /var/log/ids/state/"
info "- Baseline: /var/log/ids/baseline.dat"
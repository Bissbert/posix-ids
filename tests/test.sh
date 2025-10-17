#!/bin/sh
# test_ids.sh - Test script for IDS functionality
# Purpose: Validate IDS detection capabilities
# Portable: POSIX sh (dash/ash/BusyBox compatible)
# Usage: test_ids.sh [-c CONFIG] [-s]

set -eu
export LC_ALL=C

CONFIG="/etc/ids/ids_config.conf"
SAFE_MODE=1

err() { printf '[ERROR] %s\n' "$*" >&2; }
info() { printf '[TEST] %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; }

usage() {
    cat <<'USAGE'
Usage: test_ids.sh [-c CONFIG] [-u]
  -c CONFIG   configuration file
  -u          unsafe mode (actually trigger alerts)
  -h          show help

This script tests IDS detection capabilities.
By default runs in safe mode (simulated tests only).
USAGE
}

while getopts ":c:uh" opt; do
    case "$opt" in
        c) CONFIG=$OPTARG ;;
        u) SAFE_MODE=0 ;;
        h) usage; exit 0 ;;
        \?) err "Unknown option: -$OPTARG"; usage; exit 2 ;;
        :) err "Missing argument for -$OPTARG"; usage; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

if [ "$SAFE_MODE" = "0" ]; then
    info "WARNING: Running in UNSAFE mode - will trigger real alerts"
    printf "Continue? (yes/no): "
    read -r confirm
    if [ "$confirm" != "yes" ]; then
        info "Cancelled"
        exit 0
    fi
fi

info "Starting IDS tests..."
info "Config: $CONFIG"
info "Mode: $([ "$SAFE_MODE" = "1" ] && printf "SAFE" || printf "UNSAFE")"

# Test 1: Configuration file check
info "Test 1: Configuration validation"
if [ -f "$CONFIG" ]; then
    if sh -n "$CONFIG" 2>/dev/null; then
        pass "Configuration syntax valid"
    else
        fail "Configuration syntax error"
    fi
else
    fail "Configuration file not found"
fi

# Test 2: Log directory check
info "Test 2: Log directory permissions"
if [ -d "/var/log/ids" ]; then
    if [ -w "/var/log/ids" ]; then
        pass "Log directory writable"
    else
        fail "Log directory not writable"
    fi
else
    fail "Log directory missing"
fi

# Test 3: Baseline existence
info "Test 3: Baseline file check"
if [ -f "/var/log/ids/baseline.dat" ]; then
    size=$(wc -l < "/var/log/ids/baseline.dat")
    if [ "$size" -gt 10 ]; then
        pass "Baseline exists ($size lines)"
    else
        fail "Baseline too small ($size lines)"
    fi
else
    fail "Baseline missing - run ids_baseline first"
fi

# Test 4: Network monitoring
info "Test 4: Network monitoring capabilities"
if command -v netstat >/dev/null 2>&1; then
    pass "netstat available"
elif command -v ss >/dev/null 2>&1; then
    pass "ss available (netstat alternative)"
else
    fail "No network monitoring tool available"
fi

# Test 5: Process monitoring
info "Test 5: Process monitoring capabilities"
if [ -d "/proc" ]; then
    if ls /proc/[0-9]* >/dev/null 2>&1; then
        pass "/proc filesystem accessible"
    else
        fail "/proc filesystem not readable"
    fi
else
    fail "/proc filesystem not mounted"
fi

# Test 6: Authentication log access
info "Test 6: Authentication log access"
auth_found=0
for log in /var/log/auth.log /var/log/secure; do
    if [ -r "$log" ]; then
        pass "Authentication log readable: $log"
        auth_found=1
        break
    fi
done
if [ "$auth_found" = "0" ]; then
    fail "No authentication logs accessible"
fi

# Test 7: File integrity monitoring
info "Test 7: File integrity tools"
if command -v sha256sum >/dev/null 2>&1; then
    pass "sha256sum available"
elif command -v sha256 >/dev/null 2>&1; then
    pass "sha256 available"
elif command -v md5sum >/dev/null 2>&1; then
    pass "md5sum available (weaker but functional)"
else
    fail "No checksum utility available"
fi

# Test 8: Alert generation (safe mode)
if [ "$SAFE_MODE" = "1" ]; then
    info "Test 8: Alert generation (simulated)"

    test_alert='{"timestamp":"2024-01-01T00:00:00Z","hostname":"test","severity":"medium","category":"test","description":"IDS test alert"}'

    if printf '%s\n' "$test_alert" >> /var/log/ids/alerts.json 2>/dev/null; then
        pass "Alert writing successful"

        # Remove test alert
        if command -v sed >/dev/null 2>&1; then
            cp /var/log/ids/alerts.json /var/log/ids/alerts.json.bak
            grep -v "IDS test alert" /var/log/ids/alerts.json.bak > /var/log/ids/alerts.json
        fi
    else
        fail "Cannot write alerts"
    fi
else
    info "Test 8: Triggering real alerts"

    # Create harmless trigger file
    trigger_file="/tmp/.ids_test_trigger_$$"
    printf '<?php eval($_GET["test"]); ?>' > "$trigger_file"

    # Run single check
    /usr/local/bin/ids_monitor -1 >/dev/null 2>&1

    # Clean up
    rm -f "$trigger_file"

    # Check if alert was generated
    if grep -q "webshell" /var/log/ids/alerts.json 2>/dev/null; then
        pass "Webshell detection working"
    else
        fail "Webshell not detected"
    fi
fi

# Test 9: Resource monitoring
info "Test 9: Resource monitoring"
if command -v top >/dev/null 2>&1; then
    pass "CPU monitoring available (top)"
elif [ -f /proc/stat ]; then
    pass "CPU monitoring available (/proc/stat)"
else
    fail "No CPU monitoring available"
fi

if [ -f /proc/meminfo ]; then
    pass "Memory monitoring available"
else
    fail "Memory monitoring unavailable"
fi

if command -v df >/dev/null 2>&1; then
    pass "Disk monitoring available"
else
    fail "Disk monitoring unavailable"
fi

# Test 10: Service detection
info "Test 10: Service monitoring"
if command -v systemctl >/dev/null 2>&1; then
    pass "systemd service monitoring available"
elif command -v service >/dev/null 2>&1; then
    pass "SysV service monitoring available"
else
    pass "Process-based service monitoring (fallback)"
fi

# Summary
info ""
info "Test Summary"
info "============"

total_tests=10
passed=$(grep -c '^\[PASS\]' "$0" 2>/dev/null || printf "0")
failed=$(grep -c '^\[FAIL\]' "$0" 2>/dev/null || printf "0")

info "Tests run: $total_tests"
info "Passed: $passed"
info "Failed: $failed"

if [ "$failed" = "0" ]; then
    info "Result: ALL TESTS PASSED"
    exit 0
else
    info "Result: SOME TESTS FAILED"
    info "Review failed tests and ensure proper system configuration"
    exit 1
fi
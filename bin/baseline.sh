#!/bin/sh
# IDS Baseline Generator
# Creates initial baseline for system state
# Run this on a clean, trusted system before monitoring

BASELINE_DIR="/var/lib/ids/baseline"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")

echo "=== IDS Baseline Generator ==="
echo "Creating baseline at: $BASELINE_DIR"
echo "Timestamp: $TIMESTAMP"

# Create directories
mkdir -p "$BASELINE_DIR/hashes" "$BASELINE_DIR/configs" "$BASELINE_DIR/system"

# System binary hashes
echo "Generating system binary hashes..."
for dir in /bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib /usr/lib64; do
    if [ -d "$dir" ]; then
        echo "  Hashing $dir..."
        find "$dir" -type f -exec md5sum {} \; 2>/dev/null | \
            sort > "$BASELINE_DIR/hashes/$(echo "$dir" | tr / _).md5"
    fi
done

# SUID/SGID files
echo "Listing SUID/SGID files..."
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | \
    sort > "$BASELINE_DIR/system/suid_sgid_files.txt"

# User accounts and groups
echo "Saving user and group information..."
cp /etc/passwd "$BASELINE_DIR/system/passwd.$TIMESTAMP"
cp /etc/group "$BASELINE_DIR/system/group.$TIMESTAMP"
cp /etc/shadow "$BASELINE_DIR/system/shadow.$TIMESTAMP" 2>/dev/null

# Installed packages
echo "Recording installed packages..."
if command -v dpkg >/dev/null 2>&1; then
    dpkg -l > "$BASELINE_DIR/system/packages_dpkg.txt"
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa > "$BASELINE_DIR/system/packages_rpm.txt"
elif command -v pacman >/dev/null 2>&1; then
    pacman -Q > "$BASELINE_DIR/system/packages_pacman.txt"
fi

# Network configuration
echo "Saving network configuration..."
ifconfig -a > "$BASELINE_DIR/system/network_interfaces.txt" 2>/dev/null || \
    ip addr show > "$BASELINE_DIR/system/network_interfaces.txt" 2>/dev/null
netstat -tuln > "$BASELINE_DIR/system/listening_ports.txt" 2>/dev/null || \
    ss -tuln > "$BASELINE_DIR/system/listening_ports.txt" 2>/dev/null
iptables -L -n -v > "$BASELINE_DIR/system/firewall_rules.txt" 2>/dev/null

# Running services
echo "Recording running services..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --all > "$BASELINE_DIR/system/services_systemd.txt"
else
    service --status-all > "$BASELINE_DIR/system/services_sysv.txt" 2>/dev/null
fi

# Kernel modules
echo "Listing kernel modules..."
lsmod > "$BASELINE_DIR/system/kernel_modules.txt"

# Cron jobs
echo "Backing up cron jobs..."
mkdir -p "$BASELINE_DIR/configs/cron"
cp /etc/crontab "$BASELINE_DIR/configs/cron/crontab" 2>/dev/null
cp -r /etc/cron.d "$BASELINE_DIR/configs/cron/" 2>/dev/null
cp -r /var/spool/cron "$BASELINE_DIR/configs/cron/user_crons" 2>/dev/null

# Critical configuration files
echo "Backing up critical configuration files..."
CONFIG_FILES="
/etc/ssh/sshd_config
/etc/sudoers
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/resolv.conf
/etc/nsswitch.conf
/etc/pam.d/common-auth
/etc/pam.d/sshd
/etc/security/limits.conf
/etc/sysctl.conf
/etc/rsyslog.conf
/etc/logrotate.conf
"

for config in $CONFIG_FILES; do
    if [ -f "$config" ]; then
        cp "$config" "$BASELINE_DIR/configs/$(basename "$config").$TIMESTAMP" 2>/dev/null
        md5sum "$config" >> "$BASELINE_DIR/configs/config_hashes.md5" 2>/dev/null
    fi
done

# Process baseline
echo "Creating process baseline..."
ps auxf > "$BASELINE_DIR/system/process_tree.txt"
ps aux | awk '{print $11}' | sort -u > "$BASELINE_DIR/system/unique_processes.txt"

# Open files and connections
echo "Recording open files and connections..."
lsof > "$BASELINE_DIR/system/open_files.txt" 2>/dev/null
lsof -i > "$BASELINE_DIR/system/network_connections.txt" 2>/dev/null

# System information
echo "Gathering system information..."
uname -a > "$BASELINE_DIR/system/kernel_info.txt"
cat /proc/version > "$BASELINE_DIR/system/proc_version.txt" 2>/dev/null
df -h > "$BASELINE_DIR/system/disk_usage.txt"
free -m > "$BASELINE_DIR/system/memory_usage.txt" 2>/dev/null
mount > "$BASELINE_DIR/system/mount_points.txt"

# File permissions for important directories
echo "Recording directory permissions..."
ls -la / > "$BASELINE_DIR/system/root_dir_listing.txt"
ls -la /etc > "$BASELINE_DIR/system/etc_dir_listing.txt"
ls -la /tmp > "$BASELINE_DIR/system/tmp_dir_listing.txt"
ls -la /var/tmp > "$BASELINE_DIR/system/vartmp_dir_listing.txt"

# SSH keys and authorized_keys
echo "Checking SSH keys..."
find /home -name "authorized_keys" -o -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | \
    while read keyfile; do
        echo "$keyfile" >> "$BASELINE_DIR/system/ssh_key_locations.txt"
        if [ -f "$keyfile" ]; then
            md5sum "$keyfile" >> "$BASELINE_DIR/system/ssh_key_hashes.md5"
        fi
    done

# Web directories baseline
echo "Creating web directory baseline..."
for web_dir in /var/www /usr/share/nginx/html /opt/lampp/htdocs; do
    if [ -d "$web_dir" ]; then
        find "$web_dir" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" \) 2>/dev/null | \
            head -1000 | while read file; do
                md5sum "$file" >> "$BASELINE_DIR/hashes/web_files.md5" 2>/dev/null
            done
    fi
done

# Startup scripts
echo "Backing up startup scripts..."
mkdir -p "$BASELINE_DIR/configs/init"
if [ -d /etc/systemd/system ]; then
    ls -la /etc/systemd/system > "$BASELINE_DIR/configs/init/systemd_services.txt"
fi
if [ -d /etc/init.d ]; then
    ls -la /etc/init.d > "$BASELINE_DIR/configs/init/init_scripts.txt"
fi
if [ -f /etc/rc.local ]; then
    cp /etc/rc.local "$BASELINE_DIR/configs/init/rc.local.$TIMESTAMP"
fi

# Create baseline summary
echo "Creating baseline summary..."
cat > "$BASELINE_DIR/baseline_summary.txt" << EOF
IDS Baseline Summary
====================
Generated: $TIMESTAMP
Hostname: $(hostname)
Kernel: $(uname -r)
OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)

File Counts:
- System binaries: $(find /bin /sbin /usr/bin /usr/sbin -type f 2>/dev/null | wc -l)
- SUID files: $(find / -perm -4000 2>/dev/null | wc -l)
- SGID files: $(find / -perm -2000 2>/dev/null | wc -l)
- User accounts: $(wc -l < /etc/passwd)
- Groups: $(wc -l < /etc/group)
- Kernel modules: $(lsmod | wc -l)
- Listening ports: $(netstat -tuln 2>/dev/null | grep LISTEN | wc -l)
- Running processes: $(ps aux | wc -l)

Checksums:
$(find "$BASELINE_DIR/hashes" -name "*.md5" -exec wc -l {} \; 2>/dev/null)

Configuration backups:
$(ls -la "$BASELINE_DIR/configs" 2>/dev/null | wc -l) files

This baseline should be stored securely and used for comparison during monitoring.
EOF

# Create verification script
echo "Creating verification script..."
cat > "$BASELINE_DIR/verify_baseline.sh" << 'VERIFY_EOF'
#!/bin/sh
# Verify current system against baseline

BASELINE_DIR="/var/lib/ids/baseline"
REPORT_FILE="/tmp/baseline_verification_$(date +%Y%m%d_%H%M%S).txt"

echo "Baseline Verification Report" > "$REPORT_FILE"
echo "============================" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Verify system binaries
echo "Checking system binaries..." >> "$REPORT_FILE"
for hash_file in "$BASELINE_DIR/hashes"/*.md5; do
    if [ -f "$hash_file" ]; then
        echo "  Checking $(basename "$hash_file" .md5)..." >> "$REPORT_FILE"
        while read hash file; do
            if [ -f "$file" ]; then
                current_hash=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
                if [ "$current_hash" != "$hash" ]; then
                    echo "    CHANGED: $file" >> "$REPORT_FILE"
                fi
            else
                echo "    MISSING: $file" >> "$REPORT_FILE"
            fi
        done < "$hash_file"
    fi
done

# Check for new SUID/SGID files
echo "" >> "$REPORT_FILE"
echo "Checking SUID/SGID files..." >> "$REPORT_FILE"
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort > /tmp/current_suid.txt
diff "$BASELINE_DIR/system/suid_sgid_files.txt" /tmp/current_suid.txt >> "$REPORT_FILE" 2>/dev/null
rm /tmp/current_suid.txt

# Check user accounts
echo "" >> "$REPORT_FILE"
echo "Checking user accounts..." >> "$REPORT_FILE"
diff "$BASELINE_DIR/system/passwd."* /etc/passwd >> "$REPORT_FILE" 2>/dev/null

echo "" >> "$REPORT_FILE"
echo "Verification complete. Report saved to: $REPORT_FILE"
cat "$REPORT_FILE"
VERIFY_EOF

chmod +x "$BASELINE_DIR/verify_baseline.sh"

# Generate JSON summary for Splunk
echo "Generating JSON summary for Splunk..."
cat > "$BASELINE_DIR/baseline_splunk.json" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "event_type": "baseline_created",
  "host": "$(hostname)",
  "baseline_stats": {
    "system_binaries": $(find /bin /sbin /usr/bin /usr/sbin -type f 2>/dev/null | wc -l),
    "suid_files": $(find / -perm -4000 2>/dev/null | wc -l),
    "sgid_files": $(find / -perm -2000 2>/dev/null | wc -l),
    "user_accounts": $(wc -l < /etc/passwd),
    "kernel_modules": $(lsmod | wc -l),
    "listening_ports": $(netstat -tuln 2>/dev/null | grep LISTEN | wc -l),
    "running_processes": $(ps aux | wc -l)
  },
  "baseline_location": "$BASELINE_DIR"
}
EOF

echo ""
echo "=== Baseline Generation Complete ==="
echo "Baseline stored in: $BASELINE_DIR"
echo "Verification script: $BASELINE_DIR/verify_baseline.sh"
echo ""
echo "IMPORTANT: Secure this baseline directory and create an offline backup!"
echo "Run the verification script periodically to detect changes."
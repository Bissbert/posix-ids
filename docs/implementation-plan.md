# Linux Intrusion Detection System Implementation Plan

## Executive Summary
This document outlines a comprehensive intrusion detection system for Linux servers using minimal resources and POSIX-compliant tools, optimized for Splunk ingestion.

## 1. Network-Based Threats

### 1.1 Port Scanning Detection
**What to Monitor:**
- Rapid connection attempts to multiple ports
- SYN floods and half-open connections
- Failed connection attempts from single sources

**Log Files/Commands:**
```bash
# Primary sources
/var/log/kern.log          # Kernel firewall logs
/var/log/ufw.log           # UFW firewall logs
/var/log/iptables.log      # iptables logs
netstat -tuln              # Active connections
ss -tuln                   # Socket statistics
```

**Detection Patterns:**
```regex
# Port scan patterns
SYN_SENT.*:([0-9]+).*from=([0-9.]+)
DPT=([0-9]+).*SRC=([0-9.]+).*FLAGS=.*S
Connection refused.*from.*port.*([0-9]+)
```

**IoCs:**
- >10 different ports accessed within 60 seconds from same IP
- >50 SYN packets without ACK from single source
- Sequential port access patterns (1000, 1001, 1002...)

**Check Frequency:** Every 30 seconds for active monitoring

**Splunk Format:**
```json
{
  "timestamp": "2025-01-17T10:30:45Z",
  "event_type": "network_threat",
  "threat_category": "port_scan",
  "source_ip": "192.168.1.100",
  "destination_ports": [22, 80, 443, 3306],
  "severity": "medium",
  "detection_method": "threshold_exceeded",
  "host": "server01"
}
```

### 1.2 Brute Force Attacks
**What to Monitor:**
- Failed SSH/FTP/HTTP authentication attempts
- Password spray attacks
- Credential stuffing patterns

**Log Files/Commands:**
```bash
/var/log/auth.log          # Authentication logs
/var/log/secure            # RHEL/CentOS auth logs
/var/log/apache2/access.log
/var/log/nginx/access.log
journalctl -u sshd         # SystemD SSH logs
```

**Detection Patterns:**
```regex
# SSH brute force
Failed password for .* from ([0-9.]+)
Invalid user .* from ([0-9.]+)
Connection closed by ([0-9.]+).*\[preauth\]

# HTTP brute force
POST.*/(login|admin|wp-login).*401
```

**IoCs:**
- >5 failed logins within 60 seconds from same IP
- Multiple usernames tried from single IP
- Known default credentials attempted

**Check Frequency:** Every 60 seconds

### 1.3 Malicious Traffic Patterns
**What to Monitor:**
- Outbound connections to known C2 servers
- Unusual DNS queries
- Data exfiltration patterns

**Log Files/Commands:**
```bash
tcpdump -i any -n          # Packet capture
/var/log/named/query.log   # DNS queries
iftop                      # Bandwidth monitoring
nethogs                    # Process network usage
```

**Detection Patterns:**
```regex
# Suspicious DNS
query:.*\.(tk|ml|ga|cf)   # Free domains often used maliciously
([a-z0-9]{32,})\..+       # DGA domains
query:.*base64.*          # Base64 encoded DNS tunneling
```

**IoCs:**
- DNS queries >63 characters (DNS tunneling)
- Connections to non-standard ports for protocols
- Large data transfers to uncommon destinations

**Check Frequency:** Every 2 minutes

## 2. File System Integrity Monitoring

### 2.1 Critical File Modifications
**What to Monitor:**
- System binaries (/bin, /sbin, /usr/bin, /usr/sbin)
- Configuration files (/etc)
- Boot files (/boot)
- Library files (/lib, /lib64)

**Log Files/Commands:**
```bash
# File integrity checking
find /bin /sbin -type f -exec md5sum {} \;
stat -c '%n %Y %a %U %G %s' /etc/passwd
ls -la /etc/ | md5sum      # Directory fingerprint
inotifywait -mr /etc/      # Real-time monitoring
```

**Detection Patterns:**
```bash
# Changed file detection
CHECKSUM_MISMATCH=".*checksum.*differ"
PERMISSION_CHANGE="mode.*changed from.*to"
OWNER_CHANGE="ownership.*changed"
```

**IoCs:**
- Binary checksum changes
- SUID/SGID bit additions
- New files in system directories
- Timestamp anomalies (future dates, all same time)

**Check Frequency:**
- Critical binaries: Every 5 minutes
- Configuration files: Every 15 minutes
- Full scan: Daily

**Splunk Format:**
```json
{
  "timestamp": "2025-01-17T10:30:45Z",
  "event_type": "file_integrity",
  "action": "modified",
  "file_path": "/bin/ls",
  "old_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "new_hash": "098f6bcd4621d373cade4e832627b4f6",
  "permissions": "755",
  "owner": "root",
  "severity": "critical",
  "host": "server01"
}
```

### 2.2 Rootkit Detection
**What to Monitor:**
- Hidden files and processes
- Kernel module modifications
- System call table modifications

**Log Files/Commands:**
```bash
ls -la / | grep "^\."      # Hidden files
ps aux | wc -l vs /proc/*/stat | wc -l  # Process hiding
lsmod | md5sum            # Kernel module changes
```

**Detection Patterns:**
- Discrepancies between ps and /proc
- Files starting with "..." or unusual characters
- Kernel modules not in standard locations

**Check Frequency:** Every 10 minutes

### 2.3 Web Shell Detection
**What to Monitor:**
- Web directories for suspicious PHP/JSP/ASP files
- Recently modified web files
- Files with suspicious content patterns

**Log Files/Commands:**
```bash
find /var/www -name "*.php" -mtime -1
grep -r "eval\|exec\|system\|shell_exec" /var/www/
```

**Detection Patterns:**
```regex
# Web shell signatures
(eval|assert|system|exec|passthru|shell_exec)\s*\(
base64_decode.*eval
$_POST\[.*\]\s*\(
```

**Check Frequency:** Every 30 minutes

## 3. User and Authentication Anomalies

### 3.1 Suspicious User Activity
**What to Monitor:**
- New user account creation
- User privilege changes
- Unusual login times/locations
- Concurrent sessions from different locations

**Log Files/Commands:**
```bash
/var/log/auth.log
/etc/passwd (monitor changes)
/etc/shadow (monitor changes)
/etc/group (monitor changes)
last -f /var/log/wtmp     # Login history
w                          # Current users
who -a                     # All logged users
```

**Detection Patterns:**
```regex
# Suspicious authentication
useradd.*-u 0              # UID 0 user creation
usermod.*-G.*sudo|wheel    # Privilege escalation
Accepted.*from.*([0-9.]+).*port.*([0-9]+)
session opened for user (.*) by \(uid=0\)
```

**IoCs:**
- Login from unusual geographic locations
- Login outside business hours
- Multiple failed then successful login
- Service accounts with interactive shells

**Check Frequency:** Every 2 minutes

**Splunk Format:**
```json
{
  "timestamp": "2025-01-17T10:30:45Z",
  "event_type": "authentication",
  "action": "login",
  "username": "admin",
  "source_ip": "203.0.113.1",
  "source_port": 54321,
  "auth_method": "password",
  "session_id": "pts/1",
  "geo_location": "CN",
  "anomaly_score": 8.5,
  "severity": "high",
  "host": "server01"
}
```

### 3.2 Privilege Escalation Attempts
**What to Monitor:**
- sudo usage patterns
- su attempts
- SUID/SGID binary execution
- Capability changes

**Log Files/Commands:**
```bash
/var/log/auth.log          # sudo logs
find / -perm -4000 2>/dev/null  # SUID files
getcap -r / 2>/dev/null    # File capabilities
```

**Detection Patterns:**
```regex
# Privilege escalation
sudo:.*COMMAND=.*(/bin/bash|/bin/sh)
su\[.*\]:.*FAILED.*authentication
Attempt to use.*sudo.*by.*non-sudoer
```

**IoCs:**
- Rapid sudo attempts
- New SUID binaries
- Unusual capability assignments
- Direct root login attempts

**Check Frequency:** Real-time for auth.log, every 5 minutes for SUID scan

## 4. Process and Service Monitoring

### 4.1 Malicious Process Detection
**What to Monitor:**
- Processes with suspicious names
- Hidden processes
- CPU/Memory intensive processes
- Network-active processes

**Log Files/Commands:**
```bash
ps auxf                    # Full process tree
lsof -i                   # Network connections by process
top -b -n 1               # Resource usage
/proc/*/exe               # Executable paths
```

**Detection Patterns:**
```bash
# Suspicious processes
CRYPTO_MINER="(xmrig|minerd|cgminer)"
SUSPICIOUS_NAME="^[0-9]+$|^\[.*\]$|^-"
DELETED_BINARY="(deleted)"
```

**IoCs:**
- Process names mimicking system processes ([kworker], systemd-*)
- Processes running from /tmp, /var/tmp, /dev/shm
- Deleted binaries still running
- Processes with randomized names

**Check Frequency:** Every 60 seconds

**Splunk Format:**
```json
{
  "timestamp": "2025-01-17T10:30:45Z",
  "event_type": "process",
  "action": "detected",
  "pid": 12345,
  "ppid": 1,
  "name": "xmrig",
  "path": "/tmp/.hidden/xmrig",
  "user": "www-data",
  "cpu_percent": 95.5,
  "memory_mb": 512,
  "network_connections": 3,
  "threat_category": "cryptominer",
  "severity": "high",
  "host": "server01"
}
```

### 4.2 Service Manipulation
**What to Monitor:**
- New services created
- Service configuration changes
- Unauthorized service starts/stops

**Log Files/Commands:**
```bash
systemctl list-units --all
/var/log/syslog           # System logs
journalctl -xe            # SystemD journal
chkconfig --list          # SysV services
```

**Detection Patterns:**
```regex
# Service anomalies
Started.*\.service
Created.*systemd.*service
Loaded:.*masked
Failed to start.*service
```

**IoCs:**
- Services with generic names
- Services running from user directories
- Masked legitimate services
- Services with @ in unusual contexts

**Check Frequency:** Every 5 minutes

## 5. System Resource Abuse

### 5.1 Resource Exhaustion Attacks
**What to Monitor:**
- CPU usage spikes
- Memory consumption
- Disk I/O patterns
- Network bandwidth

**Log Files/Commands:**
```bash
vmstat 1 5                # System statistics
iostat -x 1 5            # I/O statistics
df -h                    # Disk usage
free -m                  # Memory usage
```

**Detection Patterns:**
- CPU >90% for >5 minutes
- Memory usage >95%
- Disk usage increasing >1GB/minute
- Fork bombs (process count spikes)

**IoCs:**
- Sustained high resource usage
- Rapid file creation in /tmp
- Unusual number of processes from single user

**Check Frequency:** Every 60 seconds

**Splunk Format:**
```json
{
  "timestamp": "2025-01-17T10:30:45Z",
  "event_type": "resource_abuse",
  "resource_type": "cpu",
  "usage_percent": 98.5,
  "duration_seconds": 300,
  "top_process": "xmrig",
  "top_process_pid": 12345,
  "severity": "high",
  "host": "server01"
}
```

### 5.2 Disk Space Attacks
**What to Monitor:**
- Rapid disk filling
- Large file creation
- Log file manipulation

**Log Files/Commands:**
```bash
du -sh /var/log/*        # Log sizes
find / -size +100M -mtime -1  # Recent large files
lsof | grep deleted      # Deleted but open files
```

**Detection Patterns:**
- Files >1GB created in non-data directories
- Log files growing >100MB/hour
- Deleted files still consuming space

**Check Frequency:** Every 15 minutes

## 6. Configuration Changes

### 6.1 Critical Configuration Monitoring
**What to Monitor:**
- SSH configuration
- Firewall rules
- Cron jobs
- System startup scripts

**Log Files/Commands:**
```bash
/etc/ssh/sshd_config
/etc/crontab and /var/spool/cron/
/etc/rc.local
/etc/systemd/system/
iptables -L -n -v        # Firewall rules
```

**Detection Patterns:**
```regex
# Configuration changes
PermitRootLogin.*yes
PasswordAuthentication.*no.*->.*yes
0.0.0.0/0.*ACCEPT
\* \* \* \* \*.*curl|wget|bash
```

**IoCs:**
- SSH root login enabled
- Firewall rules allowing all traffic
- Cron jobs with wget/curl commands
- New systemd services or timers

**Check Frequency:** Every 10 minutes

**Splunk Format:**
```json
{
  "timestamp": "2025-01-17T10:30:45Z",
  "event_type": "config_change",
  "file": "/etc/ssh/sshd_config",
  "parameter": "PermitRootLogin",
  "old_value": "no",
  "new_value": "yes",
  "severity": "critical",
  "host": "server01"
}
```

### 6.2 Package and Repository Changes
**What to Monitor:**
- New package installations
- Repository additions
- Package downgrades

**Log Files/Commands:**
```bash
/var/log/apt/history.log  # Debian/Ubuntu
/var/log/yum.log         # RHEL/CentOS
rpm -Va                  # Verify installed packages
```

**Detection Patterns:**
```regex
# Package anomalies
Install:.*netcat|nmap|tcpdump
Commandline:.*--allow-unauthenticated
Repository.*added
Downgrade:.*openssh|openssl
```

**Check Frequency:** Every 30 minutes

## 7. Privilege Escalation Attempts

### 7.1 Kernel Exploit Detection
**What to Monitor:**
- Kernel module loading
- Kernel panic/oops
- Unusual system calls

**Log Files/Commands:**
```bash
dmesg | tail -100        # Kernel messages
/var/log/kern.log
lsmod                    # Loaded modules
/proc/modules
```

**Detection Patterns:**
```regex
# Kernel exploitation
segfault at.*ip.*sp.*error
BUG: unable to handle kernel
Kernel panic
insmod|modprobe.*\.ko
```

**IoCs:**
- Kernel modules loaded from /tmp
- Segmentation faults in kernel space
- Unusual kernel parameters

**Check Frequency:** Every 5 minutes

### 7.2 Container Escape Detection
**What to Monitor:**
- Container runtime logs
- Namespace changes
- Capability usage

**Log Files/Commands:**
```bash
docker logs
/var/log/docker.log
crictl logs
nsenter usage
```

**Detection Patterns:**
```regex
# Container escape
CAP_SYS_ADMIN
--privileged
/proc/self/exe
nsenter.*--target
```

**Check Frequency:** Every 5 minutes

## Priority Matrix

### Critical Priority (Check every 30-60 seconds)
1. Active brute force attacks
2. Process anomalies (cryptominers, backdoors)
3. Authentication anomalies
4. Network scanning detection

### High Priority (Check every 2-5 minutes)
1. File integrity of system binaries
2. Privilege escalation attempts
3. Configuration changes
4. Kernel module changes

### Medium Priority (Check every 10-15 minutes)
1. Web shell detection
2. Service modifications
3. Resource usage patterns
4. Package changes

### Low Priority (Check daily)
1. Full file system integrity scan
2. User account audit
3. Log rotation and cleanup
4. Baseline updates

## Resource-Optimized Implementation

### Minimal Resource Approach
```bash
#!/bin/sh
# Lightweight IDS checker - runs every 60 seconds

# Use nice to lower priority
nice -n 10 /usr/local/bin/ids_check.sh

# Rotate between check types to spread load
MINUTE=$(date +%M)
CHECK_TYPE=$((MINUTE % 4))

case $CHECK_TYPE in
  0) check_network_threats ;;
  1) check_authentication ;;
  2) check_processes ;;
  3) check_file_integrity ;;
esac

# Write to single log file for Splunk
echo "$OUTPUT" | logger -t IDS -p local0.info
```

### Memory-Efficient Monitoring
- Use streaming commands (tail -f) instead of loading full files
- Process logs in chunks (head/tail with line limits)
- Use awk/sed for pattern matching instead of loading into memory
- Implement log rotation to prevent file size issues

### CPU-Efficient Scanning
- Stagger intensive checks across time
- Use incremental file hashing (only check modified files)
- Implement adaptive checking (increase frequency on detection)
- Use process nice values to prevent system impact

## Splunk Integration Best Practices

### Universal Log Format
```json
{
  "timestamp": "ISO8601",
  "host": "hostname",
  "source": "ids_module",
  "event_type": "category",
  "severity": "critical|high|medium|low",
  "details": {},
  "raw_log": "original log line"
}
```

### Splunk Forwarder Configuration
```conf
# inputs.conf
[monitor:///var/log/ids/detection.log]
index = security
sourcetype = linux_ids
disabled = false

[script:///usr/local/bin/ids_monitor.sh]
interval = 60
sourcetype = ids_metrics
index = security
```

### Search Optimization
- Use indexed fields for common searches
- Implement summary indexing for trend analysis
- Create saved searches for critical patterns
- Set up real-time alerts for critical events

## Conclusion

This IDS implementation provides comprehensive coverage while maintaining minimal resource usage. The modular approach allows for customization based on specific threat landscapes and system constraints. Regular tuning based on false positive rates and threat intelligence updates will optimize detection accuracy.
# Linux IDS Installation and Setup Guide

## Overview
This intrusion detection system provides comprehensive monitoring for Linux servers using minimal resources and POSIX-compliant tools. It's designed for easy integration with Splunk SIEM.

## System Requirements

### Minimum Requirements
- Linux/Unix system with POSIX shell (/bin/sh)
- 50MB disk space for scripts and logs
- 64MB RAM for monitoring processes
- Basic Unix utilities: awk, sed, grep, find, ps, netstat

### Optional Requirements (Enhanced Features)
- mail command for email alerts
- iptables for automated blocking
- inotifywait for real-time file monitoring
- auditd for advanced audit logging

## Installation Steps

### 1. Create Required Directories
```bash
# As root or with sudo
mkdir -p /opt/ids
mkdir -p /var/log/ids
mkdir -p /var/lib/ids/state
mkdir -p /var/lib/ids/baseline

# Set appropriate permissions
chmod 750 /opt/ids /var/log/ids /var/lib/ids
chown root:root /opt/ids /var/lib/ids
```

### 2. Install IDS Scripts
```bash
# Copy monitoring scripts
cp ids-monitor.sh /opt/ids/
cp ids-baseline.sh /opt/ids/
cp ids-realtime-alert.sh /opt/ids/

# Make scripts executable
chmod +x /opt/ids/*.sh

# Set secure permissions
chmod 750 /opt/ids/*.sh
chown root:root /opt/ids/*.sh
```

### 3. Generate Initial Baseline
```bash
# Run baseline generator on clean system
/opt/ids/ids-baseline.sh

# Verify baseline was created
ls -la /var/lib/ids/baseline/

# Backup baseline to secure location
tar czf /root/ids-baseline-$(date +%Y%m%d).tar.gz /var/lib/ids/baseline/
```

### 4. Configure Cron Jobs
```bash
# Add to root's crontab
crontab -e

# Add these entries:
# Main IDS monitor - runs every minute
* * * * * /opt/ids/ids-monitor.sh >/dev/null 2>&1

# Baseline verification - daily at 2 AM
0 2 * * * /var/lib/ids/baseline/verify_baseline.sh >/var/log/ids/baseline_verify.log 2>&1

# Log rotation - weekly
0 0 * * 0 /usr/bin/find /var/log/ids -name "*.json" -mtime +30 -delete
```

### 5. Setup Real-time Monitoring
```bash
# Create systemd service (if using systemd)
cat > /etc/systemd/system/ids-realtime.service << EOF
[Unit]
Description=IDS Real-time Alert Monitor
After=network.target

[Service]
Type=simple
ExecStart=/opt/ids/ids-realtime-alert.sh
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable ids-realtime
systemctl start ids-realtime

# For SysV init systems
cat > /etc/init.d/ids-realtime << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          ids-realtime
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       IDS Real-time Monitor
### END INIT INFO

case "$1" in
    start)
        /opt/ids/ids-realtime-alert.sh &
        echo $! > /var/run/ids-realtime.pid
        ;;
    stop)
        kill $(cat /var/run/ids-realtime.pid)
        rm /var/run/ids-realtime.pid
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
EOF

chmod +x /etc/init.d/ids-realtime
update-rc.d ids-realtime defaults
service ids-realtime start
```

### 6. Configure Email Alerts (Optional)
```bash
# Install mail utilities if not present
apt-get install mailutils    # Debian/Ubuntu
yum install mailx            # RHEL/CentOS

# Configure admin email in scripts
sed -i 's/security@example.com/your-email@domain.com/g' /opt/ids/*.sh

# Test email configuration
echo "Test IDS alert" | mail -s "IDS Test" your-email@domain.com
```

## Splunk Integration

### 1. Install Splunk Universal Forwarder
```bash
# Download from Splunk website
wget -O splunkforwarder.tgz "https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=latest&product=universalforwarder"

# Extract and install
tar xzf splunkforwarder.tgz -C /opt
/opt/splunkforwarder/bin/splunk start --accept-license

# Configure forwarder
/opt/splunkforwarder/bin/splunk add forward-server splunk-server:9997
/opt/splunkforwarder/bin/splunk add monitor /var/log/ids/detection.json -index security -sourcetype linux_ids
```

### 2. Deploy Splunk Configuration
```bash
# Copy configurations to Splunk
cp splunk-config/props.conf /opt/splunkforwarder/etc/system/local/
cp splunk-config/inputs.conf /opt/splunkforwarder/etc/system/local/

# Restart forwarder
/opt/splunkforwarder/bin/splunk restart
```

### 3. Import Dashboard on Splunk Server
1. Log into Splunk Web Interface
2. Go to Settings → User Interface → Views
3. Click "New View"
4. Paste contents of `splunk-dashboards/ids-dashboard.xml`
5. Save with appropriate permissions

### 4. Configure Saved Searches and Alerts
```bash
# On Splunk server
cp splunk-config/savedsearches.conf $SPLUNK_HOME/etc/apps/search/local/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

## Performance Tuning

### For Low-Resource Systems
```bash
# Adjust check frequencies in ids-monitor.sh
sed -i 's/CHECK_TYPE=$((MINUTE % 6))/CHECK_TYPE=$((MINUTE % 10))/' /opt/ids/ids-monitor.sh

# Reduce log retention
echo "0 0 * * * find /var/log/ids -name '*.json' -mtime +7 -delete" | crontab -

# Limit process monitoring
nice -n 19 /opt/ids/ids-monitor.sh
```

### For High-Security Environments
```bash
# Increase monitoring frequency
# Edit crontab to run every 30 seconds
* * * * * /opt/ids/ids-monitor.sh
* * * * * sleep 30; /opt/ids/ids-monitor.sh

# Enable all optional checks
# Uncomment all monitoring functions in ids-monitor.sh

# Enable audit logging
apt-get install auditd
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
```

## Testing the IDS

### 1. Verify Installation
```bash
# Check if monitoring is running
ps aux | grep ids-monitor
systemctl status ids-realtime

# Check for log output
tail -f /var/log/ids/detection.json

# Verify baseline
/var/lib/ids/baseline/verify_baseline.sh
```

### 2. Test Detection Capabilities
```bash
# Test file integrity monitoring
touch /bin/test_file
# Should generate alert for new file in system directory

# Test authentication monitoring
ssh invalid_user@localhost
# Should detect failed login attempt

# Test process monitoring
# Run a suspicious command
python -c "import time; time.sleep(3600)" &
# Should detect python process

# Test network monitoring
# Simulate port scan (be careful in production)
for i in {1..100}; do nc -zv localhost $i 2>&1 | grep -q succeeded && echo "Port $i open"; done
```

### 3. Verify Splunk Integration
```bash
# Check if data is being forwarded
/opt/splunkforwarder/bin/splunk list monitor

# Search in Splunk Web UI
index=security sourcetype=linux_ids earliest=-1h

# Test an alert
# Trigger a critical event and verify email/alert is received
```

## Maintenance Tasks

### Daily
- Review critical alerts
- Check IDS service status
- Monitor log file sizes

### Weekly
- Review high/medium severity events
- Update threat intelligence patterns
- Clean old log files

### Monthly
- Update baseline for legitimate changes
- Review and tune detection rules
- Audit user accounts and permissions
- Test incident response procedures

### Quarterly
- Full security audit using baseline comparison
- Update IDS scripts with new detection patterns
- Review and update documentation
- Conduct penetration testing

## Troubleshooting

### No Alerts Being Generated
```bash
# Check if monitor is running
ps aux | grep ids-monitor

# Check log file permissions
ls -la /var/log/ids/

# Run monitor manually to see errors
sh -x /opt/ids/ids-monitor.sh

# Check cron logs
grep ids /var/log/cron.log
```

### High False Positive Rate
```bash
# Review and whitelist legitimate activity
# Add exceptions to monitoring scripts

# Example: Whitelist an IP
echo "10.0.0.100" >> /opt/ids/whitelist.txt

# Update scripts to check whitelist
grep -v -f /opt/ids/whitelist.txt
```

### Performance Issues
```bash
# Check resource usage
top -b -n 1 | grep ids

# Reduce monitoring frequency
# Adjust CHECK_INTERVAL in scripts

# Use nice to lower priority
nice -n 19 ionice -c 3 /opt/ids/ids-monitor.sh
```

### Splunk Not Receiving Data
```bash
# Check forwarder status
/opt/splunkforwarder/bin/splunk status

# Test connectivity
telnet splunk-server 9997

# Check for errors
tail /opt/splunkforwarder/var/log/splunk/splunkd.log

# Verify inputs
/opt/splunkforwarder/bin/splunk list monitor
```

## Security Hardening

### Protect IDS Files
```bash
# Set immutable flag on critical files
chattr +i /opt/ids/*.sh
chattr +i /var/lib/ids/baseline/*

# Restrict log access
chmod 640 /var/log/ids/*
chown root:splunk /var/log/ids/*

# Monitor IDS files for changes
echo "/opt/ids/" >> /etc/aide.conf
```

### Secure Communications
```bash
# Use TLS for Splunk forwarding
/opt/splunkforwarder/bin/splunk set splunkd-ssl -sslVersions tls1.2

# Encrypt email alerts
# Configure GPG encryption for sensitive alerts
```

## Uninstallation

```bash
# Stop services
systemctl stop ids-realtime
systemctl disable ids-realtime

# Remove cron jobs
crontab -l | grep -v ids | crontab -

# Backup logs and baseline
tar czf /root/ids-backup-$(date +%Y%m%d).tar.gz /var/log/ids /var/lib/ids

# Remove files
rm -rf /opt/ids
rm -rf /var/log/ids
rm -rf /var/lib/ids

# Remove Splunk forwarder (if desired)
/opt/splunkforwarder/bin/splunk stop
rm -rf /opt/splunkforwarder
```

## Support and Updates

For updates and additional detection patterns:
- Review OWASP guidelines regularly
- Subscribe to security advisories for your distribution
- Monitor CVE databases for new vulnerabilities
- Join security communities and forums

## License

This IDS system is provided as-is for security monitoring purposes. Ensure compliance with your organization's policies and local regulations when implementing monitoring solutions.
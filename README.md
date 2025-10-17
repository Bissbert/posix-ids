# POSIX Linux Intrusion Detection System

[![GitHub](https://img.shields.io/badge/GitHub-posix--ids-blue)](https://github.com/Bissbert/posix-ids)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![POSIX](https://img.shields.io/badge/POSIX-Compliant-brightgreen)](docs/implementation-plan.md)

A lightweight, POSIX-compliant intrusion detection system for Linux servers with minimal dependencies and Splunk integration.

## Installation Options

### Option 1: Manual Installation
```bash
# Clone the repository
git clone https://github.com/Bissbert/posix-ids.git
cd posix-ids

# Run setup
sudo ./bin/setup.sh
```

### Option 2: Ansible Deployment (Recommended for multiple servers)
```bash
# Clone the repository
git clone https://github.com/Bissbert/posix-ids.git
cd posix-ids

# Install Ansible requirements
ansible-galaxy collection install -r collections/requirements.yml

# Deploy to all servers in inventory
ansible-playbook -i inventory/production playbooks/site.yml
```

## Quick Start

```bash
# 1. Run setup (automatically installs and starts monitoring)
sudo ./bin/setup.sh

# 2. Check it's working
sudo tail -f /var/log/ids/alerts.json

# 3. Optional: Configure alerts
sudo vi /etc/ids/ids.conf
```

That's it! The system is now monitoring for intrusions.

## Project Structure

```
.
├── bin/                # Executable scripts
│   ├── monitor.sh      # Main monitoring engine
│   ├── baseline.sh     # System baseline generator
│   ├── alert.sh        # Real-time alerting system
│   └── setup.sh        # Installation script
├── config/             # Configuration files
│   └── ids.conf        # Main configuration
├── splunk/             # Splunk integration
│   ├── inputs.conf     # Data collection config
│   ├── props.conf      # Field extraction rules
│   ├── savedsearches.conf  # Pre-built alerts
│   └── dashboard.xml   # Security dashboard
├── tests/              # Testing suite
│   └── test.sh         # System validation
└── docs/               # Documentation
    ├── INSTALLATION.md # Detailed setup guide
    └── implementation-plan.md  # Technical details
```

## What It Detects

### Active Threats
- **Brute force attacks** - SSH/login attempts
- **Port scanning** - Network reconnaissance
- **Cryptominers** - Unauthorized mining processes
- **Web shells** - Backdoor scripts
- **Privilege escalation** - Unauthorized sudo/su

### System Changes
- **File integrity** - Modified system binaries
- **User accounts** - New/modified users
- **Configuration** - SSH, cron, firewall changes
- **SUID/SGID files** - Permission escalations

### Resource Abuse
- **CPU/Memory spikes** - DoS attacks
- **Disk exhaustion** - Space filling attacks
- **Network floods** - Bandwidth abuse
- **Fork bombs** - Process explosions

## Key Features

✅ **100% POSIX Compliant** - Works on any Unix/Linux system
✅ **Minimal Dependencies** - Uses only basic Unix utilities
✅ **Low Resource Usage** - <50MB RAM, <5% CPU
✅ **Splunk Ready** - JSON logs optimized for SIEM
✅ **Real-time Alerts** - Webhook, email, syslog support
✅ **Auto-response** - Block IPs, kill processes

## Commands

```bash
# Manual scan (one-time check)
sudo /opt/ids/monitor.sh -1

# Start monitoring service
sudo systemctl start ids-monitor

# View real-time alerts
sudo /opt/ids/alert.sh -t

# Update system baseline
sudo /opt/ids/baseline.sh

# Test the system
sudo /opt/ids/tests/test.sh

# Configure alerts (webhook example)
sudo /opt/ids/alert.sh -w https://hooks.slack.com/YOUR_WEBHOOK
```

## Configuration

Edit `/etc/ids/ids.conf` to customize:
- Alert thresholds
- Check frequencies
- Log locations
- Alert destinations

Example settings:
```bash
BRUTE_FORCE_THRESHOLD=5      # Failed logins before alert
PORT_SCAN_THRESHOLD=10        # Ports/min before alert
CPU_THRESHOLD=80              # CPU % before alert
CHECK_INTERVAL=60             # Seconds between checks
```

## Splunk Integration

1. **Install Splunk Universal Forwarder**
2. **Copy Splunk configs:**
   ```bash
   cp splunk/* $SPLUNK_HOME/etc/system/local/
   ```
3. **Restart Splunk:**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```
4. **Import dashboard:**
   - Log into Splunk Web
   - Settings → Dashboards → Create New
   - Import `splunk/dashboard.xml`

## Alert Examples

### Slack Webhook
```bash
sudo /opt/ids/alert.sh -w https://hooks.slack.com/services/XXX
```

### Email Alerts
```bash
echo "admin@company.com" > /etc/ids/alert_email.conf
```

### Syslog Forward
```bash
echo "siem.company.com:514" > /etc/ids/syslog.conf
```

## Performance

| Metric | Usage |
|--------|-------|
| CPU | < 5% average |
| Memory | < 50MB |
| Disk I/O | Minimal |
| Network | None |

## Security Levels

| Severity | Response Time | Auto-action |
|----------|---------------|-------------|
| Critical | Immediate | Block IP, kill process |
| High | < 5 min | Alert only |
| Medium | < 15 min | Log only |
| Low | Daily review | Log only |

## Troubleshooting

```bash
# Check if monitoring is running
ps aux | grep ids-monitor

# View recent detections
tail -100 /var/log/ids/alerts.json | jq .

# Debug mode
sh -x /opt/ids/monitor.sh

# Check installation
/opt/ids/tests/test.sh
```

## Requirements

- POSIX shell (sh/dash/ash)
- Basic Unix tools (awk, sed, grep, ps, netstat)
- Root/sudo access
- 50MB free disk space

## Compatibility

Tested on:
- Ubuntu/Debian
- RHEL/CentOS
- Alpine Linux
- BusyBox systems
- Minimal containers

## Ansible Deployment

Deploy to multiple servers with one command:

```bash
# Deploy to staging
ansible-playbook -i inventory/staging playbooks/site.yml

# Deploy to specific hosts
ansible-playbook -i inventory/production playbooks/deploy.yml --limit web-servers

# Update existing installations
ansible-playbook -i inventory/production playbooks/update.yml

# Generate new baselines
ansible-playbook -i inventory/production playbooks/baseline.yml
```

See [README_ANSIBLE.md](README_ANSIBLE.md) for detailed Ansible documentation.

## Support

- 📖 [Detailed Installation](docs/INSTALLATION.md)
- 📋 [Implementation Plan](docs/implementation-plan.md)
- 🚀 [Ansible Deployment Guide](README_ANSIBLE.md)
- 🧪 Run `tests/test.sh` to validate setup
- 📊 Check `/var/log/ids/` for logs
- 🐛 [Report Issues](https://github.com/Bissbert/posix-ids/issues)

## License

Open source - Use for defensive security only.

---

**⚠️ Security Notice**: This is a detection system, not prevention. Deploy alongside firewalls, access controls, and incident response procedures.
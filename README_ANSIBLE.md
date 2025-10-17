# POSIX IDS - Ansible Deployment Automation

Complete Ansible automation for deploying a POSIX-compliant Linux Intrusion Detection System across your infrastructure.

## Overview

This Ansible automation provides production-ready deployment, management, and maintenance of the POSIX IDS across heterogeneous Linux environments. It supports multiple distributions, service managers, and deployment scenarios with full idempotency and rollback capabilities.

## Features

- **Multi-Distribution Support**: Ubuntu, RHEL/CentOS/Rocky, Alpine Linux
- **Service Management**: systemd, init.d, or cron-based deployment
- **Rolling Updates**: Safe, staged deployments with automatic rollback
- **Configuration Templating**: Environment-specific settings with Jinja2
- **Security**: Ansible Vault integration for secrets management
- **Monitoring Integration**: Splunk forwarder support
- **Health Checks**: Built-in validation and monitoring
- **Backup & Recovery**: Automatic backups before updates

## Quick Start

### Prerequisites

1. **Ansible Control Node**:
   ```bash
   # Install Ansible
   pip install ansible>=2.9

   # Install required collections
   ansible-galaxy collection install -r collections/requirements.yml
   ```

2. **Target Hosts**:
   - SSH access with sudo/root privileges
   - Python 3 installed
   - Supported OS: Ubuntu, RHEL/CentOS, Rocky Linux, Alpine

### Basic Deployment

1. **Configure Inventory**:
   ```bash
   # Edit inventory for your environment
   vim inventory/production/hosts.yml
   ```

2. **Set Up Vault** (for secrets):
   ```bash
   # Create vault password file
   echo "your-vault-password" > ~/.ansible/vault_pass.txt
   chmod 600 ~/.ansible/vault_pass.txt

   # Encrypt secrets file
   ansible-vault encrypt group_vars/all/vault.yml
   ```

3. **Deploy IDS**:
   ```bash
   # Full deployment to all servers
   ansible-playbook -i inventory/production playbooks/site.yml

   # Deploy to specific hosts
   ansible-playbook -i inventory/production playbooks/deploy.yml --limit ubuntu-web01

   # Dry run (check mode)
   ansible-playbook -i inventory/production playbooks/site.yml --check
   ```

## Project Structure

```
.
├── ansible.cfg                 # Ansible configuration
├── collections/
│   └── requirements.yml       # Required Ansible collections
├── inventory/
│   ├── production/           # Production environment
│   │   └── hosts.yml
│   └── staging/              # Staging environment
│       └── hosts.yml
├── group_vars/
│   └── all/
│       ├── main.yml          # Global variables
│       └── vault.yml         # Encrypted secrets
├── playbooks/
│   ├── site.yml             # Complete deployment
│   ├── deploy.yml           # Quick deployment
│   ├── update.yml           # Update existing installations
│   ├── baseline.yml         # Baseline management
│   ├── check.yml            # Health checks
│   └── remove.yml           # Uninstall IDS
├── roles/
│   ├── ids_base/            # Core installation
│   ├── ids_monitor/         # Monitoring deployment
│   ├── ids_config/          # Configuration management
│   ├── ids_alerts/          # Alert configuration
│   ├── ids_baseline/        # Baseline management
│   └── ids_splunk/          # Splunk integration
└── handlers/
    └── main.yml             # Global handlers
```

## Playbook Usage

### Complete Deployment
Deploy IDS with all features:
```bash
ansible-playbook -i inventory/production playbooks/site.yml
```

### Quick Deployment
Fast deployment without baseline generation:
```bash
ansible-playbook -i inventory/production playbooks/deploy.yml \
  -e skip_baseline_generation=true
```

### Update Existing Installation
Rolling update with automatic backup:
```bash
ansible-playbook -i inventory/production playbooks/update.yml \
  -e rolling_update_batch_size=1
```

### Generate/Update Baselines
```bash
# Generate new baseline
ansible-playbook -i inventory/production playbooks/baseline.yml \
  -e action=generate

# Verify system against baseline
ansible-playbook -i inventory/production playbooks/baseline.yml \
  -e action=verify
```

### Health Checks
```bash
# Comprehensive health check
ansible-playbook -i inventory/production playbooks/check.yml

# Quick status check
ansible-playbook -i inventory/production playbooks/check.yml \
  -e detailed_check=false
```

### Uninstall IDS
```bash
# Remove IDS (keeps logs and data)
ansible-playbook -i inventory/production playbooks/remove.yml

# Complete removal including all data
ansible-playbook -i inventory/production playbooks/remove.yml \
  -e remove_all_data=true
```

## Configuration

### Key Variables

Edit `group_vars/all/main.yml` for global settings:

```yaml
# Installation paths
ids_base_path: /opt/ids
ids_log_path: /var/log/ids
ids_config_path: /etc/ids

# Service configuration
ids_service_type: systemd  # systemd, initd, or cron
ids_check_interval: 300    # seconds

# Alert configuration
ids_alert_enabled: true
ids_alert_webhook: "{{ vault_alert_webhook }}"
ids_alert_email: security@example.com

# Monitoring thresholds
ids_thresholds:
  cpu_warning: 80
  cpu_critical: 95
  memory_warning: 85
  memory_critical: 95
```

### Environment-Specific Settings

Override defaults in inventory files:

```yaml
# inventory/production/hosts.yml
all:
  vars:
    environment: production
    ids_log_retention_days: 30
    ids_check_interval: 300

# inventory/staging/hosts.yml
all:
  vars:
    environment: staging
    ids_log_retention_days: 7
    ids_check_interval: 60
    ids_debug_enabled: true
```

### Secrets Management

Store sensitive data in encrypted vault:

```bash
# Edit vault file
ansible-vault edit group_vars/all/vault.yml

# View vault contents
ansible-vault view group_vars/all/vault.yml
```

## Advanced Usage

### Rolling Deployments

Control deployment strategy:
```bash
# Deploy to 2 hosts at a time with 10s delay
ansible-playbook -i inventory/production playbooks/site.yml \
  -e rolling_update_batch_size=2 \
  -e rolling_update_delay=10
```

### Service Types

#### systemd (default)
```yaml
ids_service_type: systemd
ids_service_enabled: true
ids_service_state: started
```

#### cron-based
```yaml
ids_service_type: cron
ids_check_interval: 300  # Run every 5 minutes
```

### Splunk Integration

Enable Splunk forwarder:
```yaml
# In inventory or group_vars
splunk_enabled: true
splunk_server: splunk.internal.com
splunk_port: 9997
```

### Custom Checks

Add custom monitoring checks:

1. Create check script in `roles/ids_config/templates/checks/`
2. Add to configuration in `group_vars/all/main.yml`:
   ```yaml
   ids_checks:
     custom_check:
       enabled: true
       interval: 600
       priority: medium
   ```

## Testing

### Syntax Check
```bash
ansible-playbook playbooks/site.yml --syntax-check
```

### Dry Run
```bash
ansible-playbook -i inventory/staging playbooks/site.yml --check --diff
```

### Molecule Tests (if available)
```bash
cd roles/ids_base
molecule test
```

## Troubleshooting

### Check IDS Status
```bash
# On control node
ansible all -i inventory/production -m command \
  -a "/opt/ids/bin/ids-status.sh"

# Using playbook
ansible-playbook -i inventory/production playbooks/check.yml
```

### View Logs
```bash
# Recent alerts
ansible all -i inventory/production -m command \
  -a "tail -20 /var/log/ids/alerts.log"

# Service logs
ansible all -i inventory/production -m command \
  -a "journalctl -u ids.service -n 50"
```

### Debug Mode
```bash
# Run with verbose output
ansible-playbook -i inventory/production playbooks/site.yml -vvv

# Enable debug in IDS
ansible all -i inventory/production -m lineinfile \
  -a "path=/etc/ids/ids.conf regexp='^DEBUG_ENABLED' line='DEBUG_ENABLED=true'"
```

## Security Best Practices

1. **Vault Usage**: Always encrypt sensitive data
2. **Privilege Escalation**: Use `become` only when needed
3. **Network Security**: Limit SSH access to control node
4. **Audit Logging**: Enable and monitor Ansible logs
5. **Key Management**: Rotate SSH keys regularly

## Maintenance

### Regular Tasks

- **Update Baselines**: Weekly or after major changes
- **Check Logs**: Monitor `/var/log/ids/` for alerts
- **Rotate Logs**: Ensure logrotate is working
- **Update IDS**: Apply updates monthly

### Backup Strategy

Automatic backups are created:
- Before updates: `/var/backups/ids/pre_update_*.tar.gz`
- Before removal: `/var/backups/ids/removal_backup_*.tar.gz`
- Baseline backups: `/var/lib/ids/baselines/*.backup`

## Support

For issues, questions, or contributions:
1. Check existing documentation
2. Review playbook examples
3. Test in staging environment first
4. Enable debug mode for troubleshooting

## License

This Ansible automation is provided as-is for deploying the POSIX IDS system.

## Commands Reference

```bash
# Deployment
ansible-playbook -i inventory/production playbooks/site.yml
ansible-playbook -i inventory/production playbooks/deploy.yml --limit webservers

# Updates
ansible-playbook -i inventory/production playbooks/update.yml
ansible-playbook -i inventory/production playbooks/baseline.yml -e action=update

# Monitoring
ansible-playbook -i inventory/production playbooks/check.yml
ansible all -i inventory/production -m command -a "/opt/ids/bin/ids-healthcheck.sh"

# Maintenance
ansible-playbook -i inventory/production playbooks/baseline.yml -e action=generate
ansible-playbook -i inventory/production playbooks/remove.yml -e confirm_removal_prompt=false
```
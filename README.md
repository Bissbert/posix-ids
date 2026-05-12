# posix-ids

![GitHub last commit](https://img.shields.io/github/last-commit/Bissbert/posix-ids)

> Zero-dependency intrusion detection for Linux servers that ships alerts as JSON straight into Splunk.

## Why

Most IDS tools require a Python runtime, a specific init system, or a proprietary agent. posix-ids runs in any POSIX sh — dash, ash, BusyBox — so it works on minimal containers, Alpine hosts, and locked-down OT appliances alike. It completes the trilogy alongside [POSIX-hardening](https://github.com/Bissbert/POSIX-hardening) and [splunk-security-alerts](https://github.com/Bissbert/splunk-security-alerts): harden the host, detect intrusions, and surface alerts in Splunk.

## Quick start

```bash
git clone https://github.com/Bissbert/posix-ids.git
cd posix-ids

# Single server — manual install
sudo ./bin/setup.sh

# Multiple servers — Ansible (recommended)
ansible-galaxy collection install -r collections/requirements.yml
ansible-playbook -i inventory/production playbooks/site.yml

# Verify it is running
sudo tail -f /var/log/ids/alerts.json
```

## How it works

- `bin/monitor.sh` — continuous monitoring loop (daemon, oneshot, or interactive). Runs checks for brute-force attempts, port scans, file integrity, SUID changes, webshells, cryptominers, hidden processes, SSH/cron config drift, and resource exhaustion. Outputs newline-delimited JSON to `/var/log/ids/alerts.json`.
- `bin/alert.sh` — reads the alert log and forwards events to a Slack-compatible webhook, email (`mail`/`sendmail`/`mailx`), or a TCP/local syslog endpoint.
- `bin/baseline.sh` — captures SHA-256 checksums of critical binaries into a baseline file used by integrity checks.
- `bin/setup.sh` — installs scripts, config, and a systemd unit (falls back to cron on non-systemd systems).
- `splunk/` — drop-in Splunk Universal Forwarder config (`inputs.conf`, `props.conf`, `savedsearches.conf`) plus a pre-built XML dashboard.
- Ansible roles in `roles/` handle multi-host deployment, logrotate, sudoers, and systemd/cron service wiring.

## Configuration

Edit `/etc/ids/ids.conf` after installation. Key variables:

| Variable | Default | Description |
|---|---|---|
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed SSH logins before alert |
| `PORT_SCAN_THRESHOLD` | `10` | Connections per IP before alert |
| `CPU_THRESHOLD` | `80` | CPU % before alert |
| `CHECK_INTERVAL` | `60` | Seconds between monitoring cycles |
| `ALERT_TO_FILE` | `1` | Write JSON to alert log |
| `ALERT_TO_SYSLOG` | `0` | Forward to syslog |

## Status

Actively maintained.

## License

MIT

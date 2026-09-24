# Baselines and operation

[← back to the overview](../README.md)

`bin/baseline.sh` writes two things. With `-n` it writes the monitor baseline:
the `sha256sum` lines for `CRITICAL_FILES` at `BASELINE_FILE`
(`/var/log/ids/baseline.dat`), which `bin/monitor.sh` compares on every pass.
With `-S` it writes the broad review snapshot under `/var/lib/ids/baseline`.
Without either flag it writes both. `-V` compares `CRITICAL_FILES` with the
monitor baseline and exits 0 when nothing changed, 1 when a recorded file
changed or disappeared, and 2 when there is no baseline.

```mermaid
flowchart TD
    S["bin/setup.sh"] --> I["install scripts and config"]
    I --> B["bin/baseline.sh"]
    B -- "-n" --> F["/var/log/ids/baseline.dat<br/>sha256 of CRITICAL_FILES"]
    B -- "-S" --> L["/var/lib/ids/baseline/<br/>hashes, configs and system snapshots"]
    M["bin/monitor.sh"] --> C["config/ids.conf"]
    C --> F
    F --> K["critical-file checksum check"]

    style S fill:#1f6feb,stroke:#58a6ff,color:#fff
    style B fill:#9e6a03,stroke:#d29922,color:#fff
    style M fill:#238636,stroke:#3fb950,color:#fff
```

The nightly job that `bin/setup.sh` installs, and the Ansible timer and cron
wrapper, run `-S` only. Rewriting the monitor baseline on a schedule would
accept any change to a critical file within a day, so that stays a manual
step after a reviewed change.

## What the review snapshot records

`bin/baseline.sh` writes a timestamped directory tree containing:

| Snapshot area | Source data |
|---|---|
| `hashes/` | MD5 lists for system binary directories and selected web files |
| `system/` | SUID/SGID paths, users and groups, packages, network, services, kernel modules, processes, system facts and directory listings |
| `configs/cron/` | system and user cron material when readable |
| `configs/` | copies and MD5 records for selected SSH, sudo, resolver, PAM, sysctl, logging and rotation files |
| `system/ssh_key_locations.txt` | selected key filenames below `/home` |
| `configs/init/` | systemd, init scripts and `rc.local` when present |
| `baseline_summary.txt` | counts and a textual summary |
| `verify_baseline.sh` | a generated verifier for hashes, SUID/SGID paths and `/etc/passwd` |
| `baseline_splunk.json` | a generated summary intended for Splunk |

The generator also attempts to collect optional command output such as
`ifconfig`, `ip`, `netstat`, `ss`, `iptables`, `lsof`, `free` and `mount`. A
missing optional command can leave an incomplete snapshot. The monitor does
not read the snapshot.

## Runtime state

The monitor creates `/var/log/ids/state` and keeps comparison files for SUID/SGID
paths, users, SSH settings, cron content and observed services. It also creates
short-lived PID lists for the process comparison and stores a last-check epoch.
The JSON alert file and monitor log are rotated when they exceed the configured
maximum size. The configured value is 10485760 bytes and the configured number
of rotated files is 5; both values come from `config/ids.conf`.

The monitor can be invoked from source for a single pass:

```sh
sh bin/monitor.sh -c config/ids.conf -1
```

That command needs the configured absolute paths and suitable permissions,
because it reads and writes `/var/log/ids` and inspects host security state.
`tools/container_run.sh` runs it inside a disposable Debian container instead.

## Service and scheduling paths

The source installer creates a systemd unit when systemd is present, otherwise
an init script, and it writes a nightly cron entry for `baseline.sh -S`. In a
Debian container without systemd it installed all scripts and the init script
and exited 0 (see [Measurement](measurement.md#installer)). The Ansible roles
deploy with systemd or cron; see [Ansible deployment](ansible-deployment.md).

## Operational limitations

- The generated baseline contains sensitive material, including copies of
  account and configuration files. It must be protected as host security data.
- The monitor's `BASELINE_AGE_WARN` setting is loaded but no check in
  `monitor.sh` uses it to emit an age warning.

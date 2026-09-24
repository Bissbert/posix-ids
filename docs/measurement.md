# Measurement

[← back to the overview](../README.md)

Every number in this documentation comes from one script run in Linux
containers:

```sh
sh tools/linux-run.sh > media/captures/linux-run.txt
```

[`tools/linux-run.sh`](../tools/linux-run.sh) mounts the repository read-only
into a disposable `debian:12-slim` container, copies it, and runs the
measurement script, the installer, the test script, the baseline generator and
the syslog priorities. It then runs [`tools/container_run.sh`](../tools/container_run.sh), which
exercises the monitor end to end in a second container. Nothing runs on the
host. The full output is
[`media/captures/linux-run.txt`](../media/captures/linux-run.txt); every block
below is taken from it.

```mermaid
flowchart LR
    R["tools/linux-run.sh"] --> A["container 1<br/>measure.sh, setup.sh,<br/>tests/test.sh, baseline, syslog"]
    R --> B["container 2<br/>tools/container_run.sh<br/>monitor end to end"]
    A --> O["media/captures/linux-run.txt"]
    B --> O
    O --> D["README and docs"]

    style R fill:#1f6feb,stroke:#58a6ff,color:#fff
    style O fill:#238636,stroke:#3fb950,color:#fff
    style D fill:#8250df,stroke:#bc8cff,color:#fff
```

## Environment

| | |
|---|---|
| Kernel | Linux 6.5.11-linuxkit, aarch64 (Docker Desktop VM) |
| Image | `debian:12-slim` (`sha256:3783cc01…906251`), Debian GNU/Linux 12 |
| `/bin/sh` | `dash` |
| Extra packages | `procps`, `net-tools` (and `git` for `measure.sh`) |
| Date | 2026-09-24 |

## Repository facts

`tools/measure.sh` sums the tracked implementation `*.sh` and `*.j2` files
(outside `README*`, `docs/`, `tools/` and `tests/`),
counts the monitor's check functions, and runs `sh -n` on every tracked shell
script:

```text
implementation shell and Jinja bytes: 75576
monitor check functions: 16
shell syntax: pass
```

## Help output

```text
bin/monitor.sh -h  exit=0
bin/alert.sh -h    exit=0
```

## Installer

`sh bin/setup.sh -s` (simulate) and then `sh bin/setup.sh` as root inside the
container:

```text
=== bin/setup.sh -s (simulate)
exit=0
[INFO] [SIMULATE] Would install: bin/monitor.sh -> /usr/local/bin/ids_monitor (perms: 755)
[INFO] [SIMULATE] Would install: bin/baseline.sh -> /usr/local/bin/ids_baseline (perms: 755)
[INFO] [SIMULATE] Would install: bin/alert.sh -> /usr/local/bin/ids_alert (perms: 755)
[INFO] [SIMULATE] Would install: ids_config.conf -> /etc/ids/ids_config.conf

=== bin/setup.sh (real install, as root, inside this container)
exit=0
[INFO] Installed: /usr/local/bin/ids_monitor
[INFO] Installed: /usr/local/bin/ids_baseline
[INFO] Installed: /usr/local/bin/ids_alert
[INFO] Installed: /etc/ids/ids_config.conf
[INFO] Created init script: /etc/init.d/ids-monitor
```

The container has no systemd, so setup writes an init.d script instead of a
unit.

## Test script

`sh tests/test.sh -c /etc/ids/ids_config.conf` in safe mode, once on the fresh
install and once with an earlier record in `alerts.json`:

```text
=== tests/test.sh after a fresh install (empty alerts.json)
exit=1
last test started: Test 10: Service monitoring
runtime [PASS] lines: 11
runtime [FAIL] lines: 1
[TEST] Tests run: 10
[TEST] Passed: 11
[TEST] Failed: 1
[TEST] Result: SOME TESTS FAILED

=== tests/test.sh with one earlier record in alerts.json
exit=1
last test started: Test 10: Service monitoring
runtime [PASS] lines: 11
runtime [FAIL] lines: 1
[TEST] Tests run: 10
[TEST] Passed: 11
[TEST] Failed: 1
[TEST] Result: SOME TESTS FAILED
```

Both runs reach Test 10. The one failure is Test 6: the container has no
`/var/log/auth.log`.

## Baseline

`bin/baseline.sh -n` writes the monitor baseline, and `-V` compares the
critical files with it straight away:

```text
=== baseline producer and monitor input
10:BASELINE_FILE="/var/log/ids/baseline.dat"
Writing monitor baseline: /var/log/ids/baseline.dat
  2 files recorded
baseline.sh -n  exit=0
/var/log/ids/baseline.dat (monitor.sh reads): present, 2 entries
OK        /etc/passwd
OK        /etc/shadow
ABSENT    /etc/sudoers
ABSENT    /etc/ssh/sshd_config
baseline.sh -V (unchanged)  exit=0
```

`/etc/sudoers` and `/etc/ssh/sshd_config` do not exist in the slim image, so
they are not recorded and `-V` reports them as absent rather than missing.

## Syslog priority

`logger --no-act` validates each priority the monitor can pass without
needing a syslog daemon; the old `security.<severity>` form is shown for
comparison:

```text
=== syslog priority built from an IDS severity
syslog_priority() {
    case "$1" in
        critical) printf 'auth.crit' ;;
        high) printf 'auth.err' ;;
        medium) printf 'auth.warning' ;;
        low) printf 'auth.notice' ;;
        *) printf 'auth.info' ;;
    esac
}
logger -p auth.crit  exit=0
logger -p auth.err  exit=0
logger -p auth.warning  exit=0
logger -p auth.notice  exit=0
logger -p auth.info  exit=0
logger -p security.medium  exit=1
```

## Monitor end to end

`tools/container_run.sh` copies `config/ids.conf` unchanged (syslog on; the
container runs no syslog daemon, so `logger` discards the messages), writes the
baseline with `bin/baseline.sh -n`, and runs `bin/monitor.sh -1` twice.
Between the passes it plants harmless test artefacts:

```text
  /var/log/auth.log         12 failed passwords from 203.0.113.9 (now)
  /var/log/auth.log         12 failed passwords from 198.51.100.4 (two days ago)
  /var/log/auth.log         15 sudo invocations (now)
  /var/www/html/uploads.php eval() one-liner
  /usr/bin/backdoor         mode 4755
  /etc/passwd               new account eviluser (uid 1337)
  /usr/local/bin/xmrig      running (a renamed sleep)
  /tmp/ghost                running, binary deleted
  /etc/ssh/sshd_config      PermitRootLogin yes
  /etc/cron.d/implant       new cron entry
```

The failed passwords from 198.51.100.4 are dated two days back, outside
`AUTH_WINDOW`, and raise no alert. The warm pass exited 0 and wrote 13 alert
records:

| Category | Record |
|---|---|
| authentication | Brute force attack detected |
| filesystem | Critical file modified (×2) |
| filesystem | New SUID/SGID file detected |
| filesystem | Potential webshell detected |
| authentication | New user created |
| authentication | Excessive failed login attempts |
| authentication | Unusual sudo activity |
| process | Potential cryptominer detected |
| process | Process running deleted binary |
| resources | High CPU usage |
| configuration | SSH configuration changed |
| configuration | Cron configuration changed |

```text
== alerts by category and severity ==
      3 filesystem critical
      2 configuration high
      2 authentication high
      1 resources medium
      1 process high
      1 process critical
      1 filesystem high
      1 authentication medium
      1 authentication critical

== resource cost of one pass ==
  wall clock (ns diff)      : 313626459
```

That is about 0.31 s for one pass in this container. It is one run, not a
benchmark.

`baseline.sh -V` after the planted changes:

```text
  CHANGED   /etc/passwd
  OK        /etc/shadow
  ABSENT    /etc/sudoers
  CHANGED   /etc/ssh/sshd_config
  exit status: 1
```

## Regression suite

`sh tests/docker.sh` is separate from the capture. It builds two images
(`debian:12-slim` with `procps`, `net-tools`, `cron` and `bsdutils`; and
`python:3.12-slim` with ansible-core 2.17) and runs every test against a
read-only mount of the repository:

| Test | Covers | Checks |
|---|---|---|
| `tests/regression/baseline_producer.sh` | [#4](https://github.com/Bissbert/posix-ids/issues/4) | 19 |
| `tests/regression/syslog_priority.sh` | [#5](https://github.com/Bissbert/posix-ids/issues/5) | 8 |
| `tests/regression/auth_window.sh` | [#6](https://github.com/Bissbert/posix-ids/issues/6) | 9 |
| `tests/static/splunk_fields.py` | [#7](https://github.com/Bissbert/posix-ids/issues/7) | 83 |
| `tests/static/ansible_refs.py` | [#8](https://github.com/Bissbert/posix-ids/issues/8), [#12](https://github.com/Bissbert/posix-ids/issues/12), [#13](https://github.com/Bissbert/posix-ids/issues/13) | 74 |
| `tests/ansible/deploy.sh` | [#8](https://github.com/Bissbert/posix-ids/issues/8), [#12](https://github.com/Bissbert/posix-ids/issues/12), [#13](https://github.com/Bissbert/posix-ids/issues/13) | 27 |
| `tests/regression/test_script.sh` | [#9](https://github.com/Bissbert/posix-ids/issues/9) | 9 |
| `tests/regression/grep_count.sh` | [#10](https://github.com/Bissbert/posix-ids/issues/10) | 4 |
| `tests/regression/set_e_abort.sh` | [#11](https://github.com/Bissbert/posix-ids/issues/11) | 6 |

```text
239 checks passed, 0 failed
```

Each test was also run with its fix reverted, and each then failed.

## Not covered

- Ansible on remote hosts or with the systemd service type. The regression
  suite deploys to `localhost` in a container with the cron service type.
- Splunk, webhooks, email and remote syslog. None was available, so no alert
  delivery was tested. The Splunk configuration is checked statically.
- The monitor's daemon mode and the init.d service; only single passes ran.

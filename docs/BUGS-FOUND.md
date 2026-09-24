# Bugs found

[← back to the overview](../README.md)

Each entry was reviewed against the source. Two are fixed on `main`. Five are
still open because the fix needs a decision about formats, schemas or
deployment scope. Two reports were rejected. One more turned up when the checks
were re-run in a Linux container. Every command below runs inside the
disposable Debian container that [`tools/linux-run.sh`](../tools/linux-run.sh)
starts (see [Measurement](measurement.md)); none of them runs on a host.

| # | Entry | Status |
|---|---|---|
| 1 | Installer names files that are not in `bin/` | Fixed in [`9f76a68`](https://github.com/Bissbert/posix-ids/commit/9f76a68) |
| 2 | Baseline generator does not produce the monitor's baseline | Fixed in [`e82f3cb`](https://github.com/Bissbert/posix-ids/commit/e82f3cb) and [`74a66ba`](https://github.com/Bissbert/posix-ids/commit/74a66ba) ([#4](https://github.com/Bissbert/posix-ids/issues/4)) |
| 3 | Syslog priority built from an IDS severity | Fixed in [`8176a18`](https://github.com/Bissbert/posix-ids/commit/8176a18) ([#5](https://github.com/Bissbert/posix-ids/issues/5)) |
| 4 | Authentication windows are line counts, not time windows | Fixed in [`8176a18`](https://github.com/Bissbert/posix-ids/commit/8176a18) ([#6](https://github.com/Bissbert/posix-ids/issues/6)) |
| 5 | Splunk input paths and field names do not match the monitor | Fixed in [`afef8d3`](https://github.com/Bissbert/posix-ids/commit/afef8d3) ([#7](https://github.com/Bissbert/posix-ids/issues/7)) |
| 6 | Test summary counts source lines, not results | Fixed in [`5a49ceb`](https://github.com/Bissbert/posix-ids/commit/5a49ceb) |
| 7 | Ansible references absent roles, includes and templates | Fixed in [`8a1a3f2`](https://github.com/Bissbert/posix-ids/commit/8a1a3f2) ([#8](https://github.com/Bissbert/posix-ids/issues/8)) |
| 8 | Legacy installation guide names another layout | Not a bug: the guide is marked legacy |
| 9 | Ansible README presents the intended tree as complete | Not a bug: the README already says it is unverified |
| 10 | Test script stops at Test 8 on a fresh install | Fixed in [`584a77c`](https://github.com/Bissbert/posix-ids/commit/584a77c) ([#9](https://github.com/Bissbert/posix-ids/issues/9)) |

## 1. Installer names files that are not in `bin/`

**Status:** fixed in [`9f76a68`](https://github.com/Bissbert/posix-ids/commit/9f76a68).

**File:** `bin/setup.sh`

**What happened:** setup looked for `ids_monitor.sh`, `generate_baseline.sh`,
`ids_alert.sh` and `ids_config.conf`, none of which exist. `sh bin/setup.sh -s`
stopped at the first missing file with exit status 1.

**What changed:** setup now installs the checked-in `bin/monitor.sh`,
`bin/baseline.sh`, `bin/alert.sh` and `config/ids.conf`. The installed names
(`ids_monitor`, `ids_baseline`, `ids_alert`, `/etc/ids/ids_config.conf`) are
unchanged.

**Check:**

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

## 2. Baseline generator does not produce the monitor's baseline

**Status:** fixed in [`e82f3cb`](https://github.com/Bissbert/posix-ids/commit/e82f3cb) and [`74a66ba`](https://github.com/Bissbert/posix-ids/commit/74a66ba) ([#4](https://github.com/Bissbert/posix-ids/issues/4)).

**Files:** `bin/baseline.sh:6-14`, `config/ids.conf:10`, `bin/monitor.sh:169-194`

**What happens:** `baseline.sh` writes timestamped MD5 lists below
`/var/lib/ids/baseline`. The monitor reads `/var/log/ids/baseline.dat` and
expects SHA-256 lines for the critical files. Nothing writes that file.

**Reproduce:** after the container install above, which also runs the
baseline generator:

```text
10:BASELINE_FILE="/var/log/ids/baseline.dat"
/var/lib/ids/baseline (baseline.sh writes): present, 43 files
/var/log/ids/baseline.dat (monitor.sh reads): absent
```

**Possible fix:** define one versioned baseline format and path, and generate
the configured critical-file entries into it atomically.

## 3. Syslog priority built from an IDS severity

**Status:** fixed in [`8176a18`](https://github.com/Bissbert/posix-ids/commit/8176a18) ([#5](https://github.com/Bissbert/posix-ids/issues/5)).

**File:** `bin/monitor.sh:96`

**What happens:** `ALERT_TO_SYSLOG=1` is the default. The monitor passes the
IDS severity straight to `logger` as `security.<severity>`. Debian's `logger`
rejects `medium`, `high` and `critical` as priority names, and the monitor runs
under `set -eu`.

**Reproduce:**

```text
96:        logger -t "ids" -p "security.$severity" "$category: $description"
logger: unknown priority name: medium
logger -p security.medium  exit=1
```

`tools/container_run.sh` turns the syslog sink off so the other checks can be
exercised.

**Possible fix:** map severities to valid priorities before calling `logger`,
as `bin/alert.sh` already does, and keep the file alert even if syslog fails.

## 4. Authentication windows are line counts, not time windows

**Status:** fixed in [`8176a18`](https://github.com/Bissbert/posix-ids/commit/8176a18) ([#6](https://github.com/Bissbert/posix-ids/issues/6)).

**Files:** `bin/monitor.sh:140`, `bin/monitor.sh:252`, `bin/monitor.sh:268`;
`config/ids.conf:20,29-30`

**What happens:** brute-force detection reads the last 1000 auth-log lines,
failed-login detection the last 500, and sudo detection the last 1000. No
timestamps are parsed. The configuration describes five-minute windows for
logins and one hour for sudo.

**Reproduce:** `tools/container_run.sh` plants auth-log lines dated
`Jan  1 00:00`, and the monitor still reports them as a brute-force attack,
excessive failed logins and unusual sudo activity (see
[Measurement](measurement.md#monitor-end-to-end)).

**Possible fix:** parse the log timestamps and count only records inside the
configured window.

## 5. Splunk input paths and field names do not match the monitor

**Status:** fixed in [`afef8d3`](https://github.com/Bissbert/posix-ids/commit/afef8d3) ([#7](https://github.com/Bissbert/posix-ids/issues/7)).

**Files:** `splunk/inputs.conf:5,15,116`, `splunk/props.conf:15-18`,
`splunk/savedsearches.conf`

**What happens:** the monitor writes JSON lines to `/var/log/ids/alerts.json`
with `timestamp`, `hostname`, `severity`, `category`, `description` and
optional `details`. `inputs.conf` watches `detection.json` and a missing
`ids-monitor.sh`. `props.conf` and the saved searches use `event_type`,
`source_ip`, `threat_category` and `process_name`, which the monitor does not
emit.

**Reproduce:** compare any record printed by `tools/container_run.sh` with
those files. Splunk itself was not run.

**Possible fix:** point the input at `alerts.json`, then either change the
searches to use `category` and `details` or change the monitor's schema.

## 6. Test summary counts source lines, not results

**Status:** fixed in [`5a49ceb`](https://github.com/Bissbert/posix-ids/commit/5a49ceb).

**File:** `tests/test.sh`

**What happened:** the summary ran `grep -c '^\[PASS\]' "$0"` on the script's
own source, so it never counted the results the tests had printed.

**What changed:** `passed` and `failed` start at 0, and the `pass` and `fail`
functions increment them.

**Check:** with the container set up so the script reaches its summary (see
entry 10), the counters match the printed results:

```text
runtime [PASS] lines: 10
runtime [FAIL] lines: 2
[TEST] Tests run: 10
[TEST] Passed: 10
[TEST] Failed: 2
[TEST] Result: SOME TESTS FAILED
```

The two failures are expected in a container: no baseline file (entry 2) and
no readable auth log. "Tests run" is a fixed number, 10, while some tests
record more than one result.

## 7. Ansible references absent roles, includes and templates

**Status:** fixed in [`8a1a3f2`](https://github.com/Bissbert/posix-ids/commit/8a1a3f2) ([#8](https://github.com/Bissbert/posix-ids/issues/8)).

**Files:** `playbooks/site.yml:20-78`, `roles/ids_baseline/tasks/main.yml:14-65`,
`roles/ids_config/tasks/main.yml:1-55`,
`roles/ids_monitor/tasks/deploy_scripts.yml:24-48`

**What happens:** `site.yml` includes `../tasks/backup.yml` and
`../handlers/restart_ids.yml` and names `ids_alerts` and `ids_splunk` roles;
none exists. Other roles reference missing templates
(`baseline-metadata.json.j2`, the alerts and checks templates,
`lib-functions.sh.j2`) and call `baseline.sh` with `--generate`, `--verify`,
`--output` and `--baseline`, which the script does not parse.

**Reproduce:**

```sh
ls tasks handlers/restart_ids.yml roles/ids_alerts roles/ids_splunk
grep -n -- '--generate\|--verify\|--output\|--baseline' roles/ids_baseline/tasks/main.yml
grep -c -- '--generate' bin/baseline.sh
```

No Ansible run was attempted and no host was contacted.

**Possible fix:** add the missing roles and templates and a real baseline CLI,
or remove the references until they exist.

## 8. Legacy installation guide names another layout

**Status:** not a bug. `docs/INSTALLATION.md` names older files such as
`ids-monitor.sh`, but it opens with a note saying it is a legacy guide and not a
procedure for the current checkout. The current install path is `bin/setup.sh`.

## 9. Ansible README presents the intended tree as complete

**Status:** not a bug. `README_ANSIBLE.md` already says, at the top, that it
describes the intended layout and has not been verified end to end. The missing
pieces themselves are entry 7.

## 10. Test script stops at Test 8 on a fresh install

**Status:** fixed in [`584a77c`](https://github.com/Bissbert/posix-ids/commit/584a77c) ([#9](https://github.com/Bissbert/posix-ids/issues/9)).

**File:** `tests/test.sh:148-155`

**What happens:** in safe mode, Test 8 appends a test alert to
`/var/log/ids/alerts.json` and then removes it with
`grep -v "IDS test alert" alerts.json.bak > alerts.json`. On a fresh install the
file holds nothing else, so `grep -v` selects no lines and exits 1. The script
runs under `set -eu`, so it stops there: Tests 9 and 10 and the summary never
run, and the exit status is 1 whether or not anything failed.

**Reproduce:** after `sh bin/setup.sh` in the container:

```text
=== tests/test.sh after a fresh install (empty alerts.json)
exit=1
last test started: Test 8: Alert generation (simulated)
runtime [PASS] lines: 6
runtime [FAIL] lines: 2
(no summary printed)
```

With one earlier record in `alerts.json` the same run completes (entry 6).

**Possible fix:** `grep -v ... || true`, or remove the test line with `sed -i`.

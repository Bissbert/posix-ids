# Bugs found during the documentation pass

[← back to the overview](../README.md)

This file records implementation and integration defects found while tracing
the checked-in code. None of the tracked runtime files were changed.

## Installer references files that are not in `bin/`

Location: `bin/setup.sh:122-124`.

What happens: setup looks for `ids_monitor.sh`, `generate_baseline.sh` and
`ids_alert.sh`, but the repository contains `monitor.sh`, `baseline.sh` and
`alert.sh`. `sh bin/setup.sh -s` prints `Source file not found:
bin/ids_monitor.sh` and exits with status `1`.

Reproduce from the repository root:

```sh
sh bin/setup.sh -s
```

The fix I would have made is:

```diff
diff --git a/bin/setup.sh b/bin/setup.sh
--- a/bin/setup.sh
+++ b/bin/setup.sh
@@
-install_script "$script_dir/ids_monitor.sh" "$PREFIX/bin/ids_monitor" 755
-install_script "$script_dir/generate_baseline.sh" "$PREFIX/bin/ids_baseline" 755
-install_script "$script_dir/ids_alert.sh" "$PREFIX/bin/ids_alert" 755
+install_script "$script_dir/monitor.sh" "$PREFIX/bin/ids_monitor" 755
+install_script "$script_dir/baseline.sh" "$PREFIX/bin/ids_baseline" 755
+install_script "$script_dir/alert.sh" "$PREFIX/bin/ids_alert" 755
```

## The baseline generator does not create the monitor's baseline input

Locations: `bin/baseline.sh:6-14`, `config/ids.conf:10-11` and
`bin/monitor.sh:169-194`.

What happens: `baseline.sh` writes timestamped MD5 files below
`/var/lib/ids/baseline`. The monitor instead reads
`/var/log/ids/baseline.dat` and prefers SHA-256 lines for the critical files.
The installer claims it creates the latter path, but its generator does not.

Reproduce in a disposable root or container by running `bin/baseline.sh`, then
checking both paths:

```sh
sh bin/baseline.sh
find /var/lib/ids/baseline -type f -print
test -f /var/log/ids/baseline.dat
```

The fix I would have made is to give the generator and monitor one shared
format and path, for example:

```diff
diff --git a/bin/baseline.sh b/bin/baseline.sh
--- a/bin/baseline.sh
+++ b/bin/baseline.sh
@@
-BASELINE_DIR="/var/lib/ids/baseline"
+BASELINE_FILE="/var/log/ids/baseline.dat"
@@
-        find "$dir" -type f -exec md5sum {} \; 2>/dev/null | \
-            sort > "$BASELINE_DIR/hashes/$(echo "$dir" | tr / _).md5"
+        find "$dir" -type f -exec sha256sum {} \; 2>/dev/null | \
+            sort >> "$BASELINE_FILE"
```

## Syslog severity names are not valid on the measured Debian image

Location: `bin/monitor.sh:95-97`.

What happens: the default configuration sets `ALERT_TO_SYSLOG=1` and uses
severity values such as `medium`. The monitor passes that value as a syslog
priority (`security.medium`). Debian's `logger` rejects it with
`unknown priority name: medium`; a direct run can therefore stop while
handling an alert. The isolated container run used for this pass disabled the
optional syslog sink so the other detections could be measured.

Reproduce on a system whose `logger` has the same priority table:

```sh
printf '%s\n' '{"severity":"medium","category":"test","description":"test"}' \
  | logger -p security.medium
```

The fix I would have made is to map IDS severities to valid syslog priorities
before calling `logger`, as `bin/alert.sh` already does:

```diff
diff --git a/bin/monitor.sh b/bin/monitor.sh
--- a/bin/monitor.sh
+++ b/bin/monitor.sh
@@
-        logger -t "ids" -p "security.$severity" "$category: $description"
+        case "$severity" in
+            critical) priority="auth.crit" ;;
+            high)     priority="auth.err" ;;
+            medium)   priority="auth.warning" ;;
+            low)      priority="auth.notice" ;;
+            *)        priority="auth.info" ;;
+        esac
+        logger -t "ids" -p "$priority" "$category: $description"
```

## The authentication windows are line-count windows, not time windows

Locations: `bin/monitor.sh:139-146`, `bin/monitor.sh:251-256` and
`bin/monitor.sh:267-272`; the configuration comments describe five-minute
windows.

What happens: brute-force detection examines the last 1000 lines, failed-login
detection examines the last 500 lines, and sudo detection examines the last
1000 lines. No timestamps are parsed. The configured comments and the
implementation therefore describe different detection windows.

Reproduce by putting more than the configured threshold of matching lines into
an old log file, with timestamps older than the stated window, and running:

```sh
sh bin/monitor.sh -c config/ids.conf -1
```

The fix I would have made is to parse the log timestamp and filter by the
current time before counting, rather than using a fixed `tail` count:

```diff
diff --git a/bin/monitor.sh b/bin/monitor.sh
--- a/bin/monitor.sh
+++ b/bin/monitor.sh
@@
-        tail -1000 "$auth_log" 2>/dev/null | \
+        awk -v now="$(date +%s)" '... keep only records in the configured window ...' \
            grep -E 'Failed password|authentication failure' | \
```

## Splunk input paths and field names do not match monitor output

Locations: `splunk/inputs.conf:5,15,116`, `splunk/props.conf:15-18`, and
the searches in `splunk/savedsearches.conf`.

What happens: the monitor writes newline-delimited JSON to
`/var/log/ids/alerts.json` with fields `timestamp`, `hostname`, `severity`,
`category`, `description` and optional `details`. The Splunk input file points
at `detection.json` and an absent `ids-monitor.sh`, while the field extraction
and saved searches use names such as `event_type`, `source_ip`,
`threat_category` and `process_name`. The checked-in monitor does not emit
those names.

Reproduce by running `sh tools/container_run.sh` and comparing one printed
alert record with the paths and searches above. Splunk itself was not run in
this workspace.

The fix I would have made starts with aligning the primary input and JSON
field names:

```diff
diff --git a/splunk/inputs.conf b/splunk/inputs.conf
--- a/splunk/inputs.conf
+++ b/splunk/inputs.conf
@@
-[monitor:///var/log/ids/detection.json]
+[monitor:///var/log/ids/alerts.json]
```

The saved searches and dashboard would then need a deliberate second change:
either query `category` and parse `details`, or change the monitor schema and
measure that new contract. This pass makes neither behaviour change.

## The test summary counts source lines, not test results

Location: `tests/test.sh:215-217`.

What happens: the summary searches the script itself for lines beginning with
the literal text `[PASS]` or `[FAIL]`. The test functions print those tokens at
runtime, but the source lines begin with `pass()` and `fail()`, so the summary
does not count the results it just produced.

Reproduce by running the test in an installed test environment and observing
that the summary counters are based on `$0`, not the test output stream.

The fix I would have made is to increment counters in the `pass` and `fail`
functions:

```diff
diff --git a/tests/test.sh b/tests/test.sh
--- a/tests/test.sh
+++ b/tests/test.sh
@@
+passed=0
+failed=0
 pass() { printf '[PASS] %s\n' "$*"; passed=$((passed + 1)); }
 fail() { printf '[FAIL] %s\n' "$*"; failed=$((failed + 1)); }
@@
-passed=$(grep -c '^\[PASS\]' "$0" 2>/dev/null || printf "0")
-failed=$(grep -c '^\[FAIL\]' "$0" 2>/dev/null || printf "0")
```

## Ansible references absent roles, includes and templates

Locations: `playbooks/site.yml:20-28,40-49,51-68`,
`roles/ids_baseline/tasks/main.yml:20-48`,
`roles/ids_config/tasks/main.yml:14-43` and
`roles/ids_monitor/tasks/deploy_scripts.yml:33-40`.

What happens: the main playbook includes files below a root `tasks/` and
`handlers/` path that are not present, and names `ids_alerts` and `ids_splunk`
roles that are not present. Other roles reference missing templates and call
`baseline.sh` with `--generate`, `--verify`, `--output` and `--baseline`
options that the checked-in shell script does not parse.

Reproduce with a vault password configured, then run:

```sh
ansible-playbook --syntax-check -i inventory/staging/hosts.yml \
  playbooks/site.yml
```

In this workspace that check was blocked earlier by the configured but absent
`~/.ansible/vault_pass.txt`; static path inspection still shows the missing
references listed above. No Ansible target host was contacted.

The fix I would have made is to either add the referenced role/task/template
files or reduce the playbooks to the implementation that actually exists. A
minimal direction would remove the absent roles and root includes until they
have real implementations:

```diff
diff --git a/playbooks/site.yml b/playbooks/site.yml
--- a/playbooks/site.yml
+++ b/playbooks/site.yml
@@
-      ansible.builtin.include_tasks: ../tasks/backup.yml
+      # Keep only a task file that exists in this repository.
@@
-    - role: ids_alerts
-    - role: ids_splunk
+    # Add these roles only after their task and template trees exist.
```

## The legacy installation guide names another layout

Location: `docs/INSTALLATION.md:35-75,80-137,154-185`.

What happens: the guide uses names such as `ids-monitor.sh`,
`ids-baseline.sh`, `ids-realtime-alert.sh`, `splunk-config/` and
`splunk-dashboards/`, while the current checkout uses `bin/monitor.sh`,
`bin/baseline.sh`, `bin/alert.sh` and `splunk/`. Its commands therefore do not
describe the files that are actually present. The warning at the top of that
document now labels it as legacy; the commands themselves remain unchanged.

Reproduce by comparing the guide's copy commands with the tracked file list:

```sh
git ls-files bin splunk docs/INSTALLATION.md
```

The fix I would have made is to replace the guide with the current, measured
paths and to keep unverified host installation steps out of the quick start:

```diff
diff --git a/docs/INSTALLATION.md b/docs/INSTALLATION.md
--- a/docs/INSTALLATION.md
+++ b/docs/INSTALLATION.md
@@
-cp ids-monitor.sh /opt/ids/
-cp ids-baseline.sh /opt/ids/
-cp ids-realtime-alert.sh /opt/ids/
+cp bin/monitor.sh /opt/ids/
+cp bin/baseline.sh /opt/ids/
+cp bin/alert.sh /opt/ids/
```

## The Ansible README presents the intended tree as complete

Location: `README_ANSIBLE.md:5-85`.

What happens: the README describes roles and deployment behavior that are not
all present in the checkout, including the alert and Splunk role layers. The
new verification note at the top points readers to the source-backed Ansible
write-up; the intended examples remain unchanged.

Reproduce by comparing the README's role tree with:

```sh
find roles -type f -print
git ls-files playbooks roles tasks handlers
```

The fix I would have made is to label the guide as intended until the role tree
and its referenced templates exist:

```diff
diff --git a/README_ANSIBLE.md b/README_ANSIBLE.md
--- a/README_ANSIBLE.md
+++ b/README_ANSIBLE.md
@@
+> Verification note: this document describes the intended Ansible layout,
+> not a verified deployment of the current checkout.
```

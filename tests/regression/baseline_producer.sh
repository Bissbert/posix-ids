#!/bin/sh
# Regression test for #4: baseline.sh must write the baseline monitor.sh
# reads (BASELINE_FILE, sha256 of CRITICAL_FILES), and the nightly job must
# not rewrite it.
. "$(dirname "$0")/../lib.sh"

new_sandbox
mkdir -p "$S/files"
echo one > "$S/files/a"
echo two > "$S/files/b"
set_conf CRITICAL_FILES "\"$S/files/a $S/files/b $S/files/absent\""

rc=0; sh "$BIN/baseline.sh" -c "$CONF" -n > "$S/gen.out" 2>&1 || rc=$?
check "baseline.sh -n exits 0" [ "$rc" -eq 0 ]
check "baseline.sh writes BASELINE_FILE from the config" [ -f "$S/baseline.dat" ]
for f in "$S/files/a" "$S/files/b"; do
    check "baseline records the sha256 of $(basename "$f")" \
        grep -qx "$(sha256sum "$f")" "$S/baseline.dat"
done
check "baseline skips a critical file that does not exist" \
    sh -c "! grep -q absent '$S/baseline.dat'"

run_monitor
check "monitor accepts the generated baseline" no_alert "Baseline file missing"
check "unchanged files raise no integrity alert" no_alert "Critical file modified"

echo changed > "$S/files/a"
run_monitor
check "a changed critical file raises an alert" has_alert "\"File: $S/files/a\""
check "the unchanged file raises none" no_alert "\"File: $S/files/b\""

rc=0; sh "$BIN/baseline.sh" -c "$CONF" -V > "$S/verify.out" 2>&1 || rc=$?
check "baseline.sh -V exits 1 when a file changed" [ "$rc" -eq 1 ]
check "baseline.sh -V names the changed file" grep -q "CHANGED  *$S/files/a" "$S/verify.out"

before=$(sha256sum "$S/baseline.dat")
rc=0; sh "$BIN/baseline.sh" -c "$CONF" -S > "$S/snap.out" 2>&1 || rc=$?
check "baseline.sh -S exits 0" [ "$rc" -eq 0 ]
check "baseline.sh -S leaves the monitor baseline alone" [ "$before" = "$(sha256sum "$S/baseline.dat")" ]
check "baseline.sh -S writes the snapshot" [ -d /var/lib/ids/baseline/hashes ]

check "the nightly cron job only refreshes the snapshot" \
    grep -q 'ids_baseline -c .*ids_config.conf -S' "$BIN/setup.sh"

finish

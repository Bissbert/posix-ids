#!/bin/sh
# Regression test for #9: tests/test.sh must run all ten tests on a fresh
# install, where alerts.json holds nothing but the test record.
. "$(dirname "$0")/../lib.sh"

cp -r "$REPO" /tmp/ids-src
sh /tmp/ids-src/bin/setup.sh > /tmp/setup.out 2>&1
check "setup.sh installs" [ -f /etc/ids/ids_config.conf ]
: > /var/log/auth.log

run_test_script() {
    RC=0
    sh "$REPO/tests/test.sh" -c /etc/ids/ids_config.conf > /tmp/test.out 2>&1 || RC=$?
}

rm -f /var/log/ids/alerts.json
run_test_script
check "fresh install: test.sh reaches Test 10" grep -q '^\[TEST\] Test 10' /tmp/test.out
check "fresh install: test.sh prints its summary" grep -q '^\[TEST\] Test Summary' /tmp/test.out
check "fresh install: no test fails" sh -c "! grep -q '^\[FAIL\]' /tmp/test.out"
check "fresh install: test.sh exits 0" [ "$RC" -eq 0 ]
check "fresh install: the baseline check passes" grep -q '^\[PASS\] Baseline covers the critical files' /tmp/test.out
check "fresh install: the test record is removed" sh -c "! grep -q 'IDS test alert' /var/log/ids/alerts.json"

echo '{"severity":"low","category":"seed","description":"earlier record"}' > /var/log/ids/alerts.json
run_test_script
check "earlier record: test.sh reaches Test 10" grep -q '^\[TEST\] Test 10' /tmp/test.out
check "earlier record: the earlier record is kept" grep -q 'earlier record' /var/log/ids/alerts.json

finish

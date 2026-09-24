#!/bin/sh
# deploy.sh - Syntax-check every playbook, then deploy the IDS to this
# container with site.yml and check that the deployed monitor runs against
# the configuration Ansible wrote (#8, #12, #13). Runs in the image built from
# tests/ansible.Dockerfile, with the repository mounted read-only at /src.

. "$(dirname -- "$0")/../lib.sh"

rm -rf /work && cp -R "$REPO" /work && cd /work || exit 2
INV=tests/ansible/inventory.yml
LOG=/tmp/ansible
mkdir -p "$LOG"
export LC_ALL=C.UTF-8 ANSIBLE_CONFIG=/work/ansible.cfg ANSIBLE_NOCOLOR=1 ANSIBLE_FORCE_COLOR=0

# Syntax: with the production inventory and no vault, as a new checkout has.
for pb in playbooks/*.yml; do
    name=$(basename "$pb")
    if ansible-playbook --syntax-check "$pb" > "$LOG/syntax-$name.log" 2>&1; then
        ok "syntax-check $name"
    else
        not_ok "syntax-check $name: $(tail -3 "$LOG/syntax-$name.log" | tr '\n' ' ')"
    fi
done

ansible-inventory --playbook-dir playbooks --host ubuntu-web01 > "$LOG/inventory.json" 2>&1
check "group_vars next to the playbooks are loaded (ids_version set)" \
    grep -q '"ids_version"' "$LOG/inventory.json"

# Deploy.
play() {
    log=$1
    shift
    RC=0
    ansible-playbook -i "$INV" "$@" > "$LOG/$log.log" 2>&1 || RC=$?
    if [ "$RC" -eq 0 ]; then ok "ansible-playbook $* exits 0"
    else not_ok "ansible-playbook $* exits $RC: $(grep -E 'fatal|ERROR' "$LOG/$log.log" | head -3 | cut -c1-300)"
    fi
}

play site playbooks/site.yml
[ "$RC" -eq 0 ] || { cat "$LOG/site.log" | tail -40; finish; }

check "ids.conf sets IDS_HOME to the log directory" grep -qx 'IDS_HOME="/var/log/ids"' /etc/ids/ids.conf
check "ids.conf sets BASELINE_FILE" grep -qx 'BASELINE_FILE="/var/log/ids/baseline.dat"' /etc/ids/ids.conf
check "ids.conf is valid shell" sh -n /etc/ids/ids.conf
check "monitor baseline covers /etc/passwd" grep -q ' /etc/passwd$' /var/log/ids/baseline.dat
check "crontab runs the cron wrapper" sh -c 'crontab -l | grep -q "ids-cron-wrapper.sh monitor"'

RC=0
/opt/ids/bin/ids-cron-wrapper.sh monitor > "$LOG/monitor.out" 2>&1 || RC=$?
check "deployed monitor pass exits 0 (got $RC)" [ "$RC" -eq 0 ]
check "deployed monitor finds its configuration" sh -c "! grep -q 'Configuration file not found' '$LOG/monitor.out'"
check "deployed monitor finds its baseline" sh -c '! grep -q "Baseline file missing" /var/log/ids/alerts.json 2>/dev/null'
check "deployed monitor sees no changed critical file" sh -c '! grep -q "Critical file modified" /var/log/ids/alerts.json 2>/dev/null'
check "deployed monitor records its run" test -s /var/log/ids/state/last_check.state

RC=0
/opt/ids/bin/ids-status.sh > "$LOG/status.out" 2>&1 || RC=$?
check "ids-status.sh exits 0 (got $RC)" [ "$RC" -eq 0 ]
RC=0
/opt/ids/bin/ids-healthcheck.sh > "$LOG/health.out" 2>&1 || RC=$?
check "ids-healthcheck.sh reports no errors (got $RC)" [ "$RC" -le 1 ]
check "ids-healthcheck.sh finds the configuration directory" sh -c "! grep -qi 'missing.*/etc/ids\\|/etc/ids.*missing' '$LOG/health.out'"

# A second deploy must not replace the baseline an operator has accepted.
before=$(stat -c %Y /var/log/ids/baseline.dat)
sleep 1
play deploy playbooks/deploy.yml
check "redeploy keeps the monitor baseline" [ "$(stat -c %Y /var/log/ids/baseline.dat)" = "$before" ]

play verify playbooks/baseline.yml -e action=verify
play snapshot playbooks/baseline.yml -e action=snapshot
check "snapshot leaves the monitor baseline alone" [ "$(stat -c %Y /var/log/ids/baseline.dat)" = "$before" ]
play check playbooks/check.yml

finish

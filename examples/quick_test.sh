#!/bin/bash
# Quick test deployment to a single host or staging environment

set -e

# Configuration
HOST="${1:-staging-01}"
INVENTORY="inventory/staging"

echo "Quick IDS Test Deployment"
echo "========================="
echo "Target host: $HOST"
echo ""

# Deploy to single host with minimal checks
echo "1. Testing connectivity..."
ansible "$HOST" -i "$INVENTORY" -m ping

echo ""
echo "2. Deploying IDS (quick mode)..."
ansible-playbook -i "$INVENTORY" playbooks/deploy.yml \
    --limit "$HOST" \
    -e skip_baseline_generation=false \
    -e ids_debug_enabled=true \
    -e ids_verbose_logging=true

echo ""
echo "3. Checking status..."
ansible "$HOST" -i "$INVENTORY" -m command \
    -a "/opt/ids/bin/ids-status.sh" --become

echo ""
echo "4. Running health check..."
ansible "$HOST" -i "$INVENTORY" -m command \
    -a "/opt/ids/bin/ids-healthcheck.sh" --become

echo ""
echo "Test deployment complete!"
echo ""
echo "To view logs:"
echo "  ansible $HOST -i $INVENTORY -m command -a 'tail -f /var/log/ids/monitor.log' --become"
echo ""
echo "To remove test installation:"
echo "  ansible-playbook -i $INVENTORY playbooks/remove.yml --limit $HOST -e confirm_removal_prompt=false"
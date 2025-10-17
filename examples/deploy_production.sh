#!/bin/bash
# Example: Deploy IDS to production environment
# This script demonstrates a typical production deployment workflow

set -e

# Configuration
INVENTORY="inventory/production"
PLAYBOOK_DIR="playbooks"
LOG_FILE="deployment_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Pre-deployment checks
log "Starting IDS deployment to production"
log "Checking prerequisites..."

# Check Ansible installation
if ! command -v ansible-playbook &> /dev/null; then
    error "ansible-playbook not found. Please install Ansible first."
fi

# Check inventory file
if [ ! -f "$INVENTORY/hosts.yml" ]; then
    error "Inventory file not found: $INVENTORY/hosts.yml"
fi

# Check vault password file
if [ ! -f ~/.ansible/vault_pass.txt ]; then
    warning "Vault password file not found. You may be prompted for vault password."
fi

# Step 1: Verify connectivity
log "Step 1: Verifying connectivity to all hosts..."
ansible all -i "$INVENTORY" -m ping || error "Failed to connect to some hosts"

# Step 2: Run pre-flight checks
log "Step 2: Running pre-flight checks..."
ansible-playbook -i "$INVENTORY" "$PLAYBOOK_DIR/check.yml" \
    -e detailed_check=false \
    --tags preflight || error "Pre-flight checks failed"

# Step 3: Syntax check
log "Step 3: Validating playbook syntax..."
ansible-playbook "$PLAYBOOK_DIR/site.yml" --syntax-check || error "Syntax check failed"

# Step 4: Dry run (optional)
read -p "Do you want to perform a dry run first? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Running dry run..."
    ansible-playbook -i "$INVENTORY" "$PLAYBOOK_DIR/site.yml" \
        --check --diff | tee -a "$LOG_FILE"

    read -p "Continue with actual deployment? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Deployment cancelled by user"
        exit 0
    fi
fi

# Step 5: Create backup
log "Step 5: Creating pre-deployment backups..."
ansible all -i "$INVENTORY" -m shell \
    -a "mkdir -p /var/backups/ids && tar czf /var/backups/ids/pre_deploy_$(date +%Y%m%d).tar.gz /opt/ids /etc/ids /var/lib/ids 2>/dev/null || true" \
    --become

# Step 6: Deploy IDS
log "Step 6: Deploying IDS..."
ansible-playbook -i "$INVENTORY" "$PLAYBOOK_DIR/site.yml" \
    -e rolling_update_batch_size=2 \
    -e rolling_update_delay=10 \
    --diff | tee -a "$LOG_FILE" || error "Deployment failed"

# Step 7: Verify deployment
log "Step 7: Verifying deployment..."
ansible-playbook -i "$INVENTORY" "$PLAYBOOK_DIR/check.yml" || warning "Some checks failed"

# Step 8: Generate initial baseline
log "Step 8: Generating initial baseline..."
ansible-playbook -i "$INVENTORY" "$PLAYBOOK_DIR/baseline.yml" \
    -e action=generate || warning "Baseline generation had issues"

# Step 9: Final status check
log "Step 9: Getting final status..."
ansible all -i "$INVENTORY" -m command \
    -a "/opt/ids/bin/ids-status.sh" \
    --become | tee -a "$LOG_FILE"

# Summary
log "====================================="
log "Deployment completed successfully!"
log "Log file: $LOG_FILE"
log "====================================="
log ""
log "Next steps:"
log "  1. Review the deployment log: $LOG_FILE"
log "  2. Monitor IDS alerts: /var/log/ids/alerts.log"
log "  3. Check service status: systemctl status ids.service"
log "  4. View real-time logs: journalctl -u ids.service -f"
log ""
log "Useful commands:"
log "  - Check status: ansible-playbook -i $INVENTORY $PLAYBOOK_DIR/check.yml"
log "  - Update IDS: ansible-playbook -i $INVENTORY $PLAYBOOK_DIR/update.yml"
log "  - View alerts: ansible all -i $INVENTORY -m command -a 'tail -20 /var/log/ids/alerts.log'"
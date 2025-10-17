#!/bin/bash
# Common maintenance tasks for IDS

INVENTORY="${INVENTORY:-inventory/production}"

show_menu() {
    echo "IDS Maintenance Tasks"
    echo "===================="
    echo "1. Check IDS status on all hosts"
    echo "2. Update IDS to latest version"
    echo "3. Generate new baselines"
    echo "4. Verify systems against baselines"
    echo "5. View recent alerts"
    echo "6. Clean old logs"
    echo "7. Restart IDS services"
    echo "8. Enable debug mode"
    echo "9. Disable debug mode"
    echo "10. Create backup"
    echo "0. Exit"
    echo ""
    echo -n "Select task: "
}

while true; do
    show_menu
    read choice

    case $choice in
        1)
            echo "Checking IDS status..."
            ansible-playbook -i "$INVENTORY" playbooks/check.yml
            ;;
        2)
            echo "Updating IDS..."
            ansible-playbook -i "$INVENTORY" playbooks/update.yml
            ;;
        3)
            echo "Generating new baselines..."
            ansible-playbook -i "$INVENTORY" playbooks/baseline.yml -e action=generate
            ;;
        4)
            echo "Verifying against baselines..."
            ansible-playbook -i "$INVENTORY" playbooks/baseline.yml -e action=verify
            ;;
        5)
            echo "Recent alerts (last 20 lines):"
            ansible all -i "$INVENTORY" -m shell \
                -a "tail -20 /var/log/ids/alerts.log 2>/dev/null || echo 'No alerts found'" \
                --become
            ;;
        6)
            echo "Cleaning logs older than 30 days..."
            ansible all -i "$INVENTORY" -m shell \
                -a "find /var/log/ids -name '*.log.*' -mtime +30 -delete" \
                --become
            ;;
        7)
            echo "Restarting IDS services..."
            ansible all -i "$INVENTORY" -m systemd \
                -a "name=ids.service state=restarted" \
                --become
            ;;
        8)
            echo "Enabling debug mode..."
            ansible all -i "$INVENTORY" -m lineinfile \
                -a "path=/etc/ids/ids.conf regexp='^DEBUG_ENABLED' line='DEBUG_ENABLED=true'" \
                --become
            ansible all -i "$INVENTORY" -m systemd \
                -a "name=ids.service state=restarted" \
                --become
            ;;
        9)
            echo "Disabling debug mode..."
            ansible all -i "$INVENTORY" -m lineinfile \
                -a "path=/etc/ids/ids.conf regexp='^DEBUG_ENABLED' line='DEBUG_ENABLED=false'" \
                --become
            ansible all -i "$INVENTORY" -m systemd \
                -a "name=ids.service state=restarted" \
                --become
            ;;
        10)
            echo "Creating backup..."
            BACKUP_NAME="ids_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            ansible all -i "$INVENTORY" -m shell \
                -a "tar czf /var/backups/ids/$BACKUP_NAME /opt/ids /etc/ids /var/lib/ids /var/log/ids" \
                --become
            echo "Backup created: /var/backups/ids/$BACKUP_NAME"
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
    esac

    echo ""
    echo "Press Enter to continue..."
    read
    clear
done
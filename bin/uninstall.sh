#!/usr/bin/env bash
#
# BlockHarbor — uninstall
#
# Usage:
#   sudo bash bin/uninstall.sh                     # full removal (with confirmations)
#   sudo bash bin/uninstall.sh --keep-data         # keep DB + backups; remove vhost + source
#   sudo bash bin/uninstall.sh --keep-db           # keep DB only
#   sudo bash bin/uninstall.sh --keep-vhost        # keep Apache config
#   sudo bash bin/uninstall.sh --force --quiet     # CI-friendly nuke (no prompts)

set -Eeuo pipefail

KEEP_DATA=0
KEEP_DB=0
KEEP_VHOST=0
FORCE=0
QUIET=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-data)   KEEP_DATA=1; shift ;;
        --keep-db)     KEEP_DB=1; shift ;;
        --keep-vhost)  KEEP_VHOST=1; shift ;;
        --force)       FORCE=1; shift ;;
        --quiet)       QUIET=1; shift ;;
        -h|--help)     sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

INSTALL_DIR="${INSTALL_DIR:-/var/www/blockharbor}"
DB_NAME="${DB_NAME:-blockharbor}"
DB_USER="${DB_USER:-blockharbor_app}"
DB_MIGRATOR="${DB_MIGRATOR:-blockharbor_migrator}"

log() { [[ $QUIET -eq 0 ]] && printf '\e[1;34m[uninstall]\e[0m %s\n' "$*"; }

confirm() {
    [[ $FORCE -eq 1 ]] && return 0
    read -r -p "$1 (y/N): " ans
    [[ "${ans,,}" =~ ^(y|yes)$ ]]
}

echo "BlockHarbor uninstall plan:"
echo "  Source dir:    $([ $KEEP_DATA -eq 0 ] && echo 'REMOVE' || echo 'keep') $INSTALL_DIR"
echo "  Database:      $([ $KEEP_DB -eq 0 ] && [ $KEEP_DATA -eq 0 ] && echo 'DROP' || echo 'keep') $DB_NAME"
echo "  DB roles:      $([ $KEEP_DB -eq 0 ] && [ $KEEP_DATA -eq 0 ] && echo 'DROP' || echo 'keep') $DB_USER, $DB_MIGRATOR"
echo "  Apache vhost:  $([ $KEEP_VHOST -eq 0 ] && echo 'REMOVE' || echo 'keep')"
echo "  Logs:          REMOVE /var/log/blockharbor"
echo "  Backups:       $([ $KEEP_DATA -eq 0 ] && echo 'REMOVE' || echo 'keep') /var/backups/blockharbor"
echo "  Cron:          REMOVE /etc/cron.d/blockharbor"
echo

confirm "Proceed with uninstall?" || { echo "Aborted."; exit 0; }

# 1. Disable + remove Apache vhost
if [[ $KEEP_VHOST -eq 0 ]]; then
    log "Removing Apache vhost"
    a2dissite blockharbor 2>/dev/null || true
    rm -f /etc/apache2/sites-available/blockharbor.conf
    apachectl configtest && systemctl reload apache2 || true
fi

# 2. Remove cron
log "Removing cron jobs"
rm -f /etc/cron.d/blockharbor

# 3. Drop DB + roles
if [[ $KEEP_DB -eq 0 && $KEEP_DATA -eq 0 ]]; then
    log "Dropping DB and roles"
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" || true
    sudo -u postgres psql -c "DROP ROLE IF EXISTS $DB_USER;" || true
    sudo -u postgres psql -c "DROP ROLE IF EXISTS $DB_MIGRATOR;" || true
fi

# 4. Remove source directory
if [[ $KEEP_DATA -eq 0 ]]; then
    log "Removing $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
fi

# 5. Remove logs
log "Removing /var/log/blockharbor"
rm -rf /var/log/blockharbor

# 6. Remove backups (keep if --keep-data)
if [[ $KEEP_DATA -eq 0 ]]; then
    log "Removing /var/backups/blockharbor"
    rm -rf /var/backups/blockharbor
fi

# 7. Remove state
rm -rf /var/lib/blockharbor

# 8. Remove hardening configs
a2disconf blockharbor-hardening 2>/dev/null || true
rm -f /etc/apache2/conf-available/blockharbor-hardening.conf

# 9. Remove fail2ban configs
rm -f /etc/fail2ban/filter.d/blockharbor.conf /etc/fail2ban/jail.d/blockharbor.conf
systemctl reload fail2ban 2>/dev/null || true

# 10. Remove logrotate
rm -f /etc/logrotate.d/blockharbor

log "Uninstall complete."

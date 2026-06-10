#!/usr/bin/env bash
#
# BlockHarbor — update from upstream
#
# Pulls latest code, installs dependencies, runs migrations, reloads Apache.
#
# Usage:
#   sudo bash bin/update.sh                # update + reload
#   sudo bash bin/update.sh --dry-run      # show what would happen
#   sudo bash bin/update.sh --branch <br>  # update to specific branch
#   sudo bash bin/update.sh --no-restart   # skip Apache reload

set -Eeuo pipefail

BRANCH="main"
DRY=0
NO_RESTART=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)     DRY=1; shift ;;
        --branch)      BRANCH="$2"; shift 2 ;;
        --no-restart)  NO_RESTART=1; shift ;;
        -h|--help)     sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

INSTALL_DIR="${INSTALL_DIR:-/var/www/blockharbor}"
cd "$INSTALL_DIR"

log() { printf '\e[1;34m[update]\e[0m %s\n' "$*"; }
run() {
    if [[ $DRY -eq 1 ]]; then
        printf '  \e[2m[dry-run] %s\e[0m\n' "$*"
    else
        log "$*"; eval "$@"
    fi
}

# Pre-update backup (always — safety)
if command -v bin/backup.sh >/dev/null 2>&1; then
    log "Pre-update backup"
    run "bash bin/backup.sh --quiet"
fi

# Fetch + checkout
run "git fetch --all"
CURRENT=$(git symbolic-ref --short HEAD)
if [[ "$CURRENT" != "$BRANCH" ]]; then
    run "git checkout $BRANCH"
fi
OLD=$(git rev-parse HEAD)
run "git pull --ff-only origin $BRANCH"
NEW=$(git rev-parse HEAD)

if [[ "$OLD" == "$NEW" ]]; then
    log "Already up to date."
    exit 0
fi

log "Updating from $OLD to $NEW"
log "Changes:"
git log --oneline "$OLD..$NEW" | head -20

# Dependencies
[[ -f composer.json ]] && run "sudo -u www-data composer install --no-progress --no-interaction --prefer-dist --no-dev"
[[ -f package.json ]]  && run "npm ci --no-audit --no-fund && npm run build"

# Migrations
[[ -x vendor/bin/phinx ]] && run "vendor/bin/phinx migrate"

# Restart
if [[ $NO_RESTART -eq 0 ]]; then
    run "apachectl configtest && systemctl reload apache2"
fi

# Ownership
run "chown -R www-data:www-data $INSTALL_DIR"
run "chmod 600 $INSTALL_DIR/.env"

log "Update complete: $(git log -1 --format='%h %s' HEAD)"

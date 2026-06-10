#!/usr/bin/env bash
#
# BlockHarbor — restore
#
# Usage:
#   sudo bash bin/restore.sh                       # interactive backup picker
#   sudo bash bin/restore.sh <backup-file>          # restore named file
#   sudo bash bin/restore.sh --latest               # restore most recent
#   sudo bash bin/restore.sh --force <backup-file>  # skip confirmation

set -Eeuo pipefail

FILE=""
FORCE=0
LATEST=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)  FORCE=1; shift ;;
        --latest) LATEST=1; shift ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) FILE="$1"; shift ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }

INSTALL_DIR="${INSTALL_DIR:-/var/www/blockharbor}"
ENV_FILE="$INSTALL_DIR/.env"
[[ -r "$ENV_FILE" ]] || { echo "Cannot read $ENV_FILE" >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a

BACKUP_DIR="${BACKUP_DIR:-/var/backups/blockharbor}"

if [[ $LATEST -eq 1 ]]; then
    FILE=$(ls -t "$BACKUP_DIR"/*.pgdump* 2>/dev/null | head -1)
    [[ -n "$FILE" ]] || { echo "No backups found in $BACKUP_DIR" >&2; exit 1; }
fi

if [[ -z "$FILE" ]]; then
    echo "Available backups:"
    select picked in "$BACKUP_DIR"/*.pgdump*; do
        FILE="$picked"; break
    done
fi

[[ -r "$FILE" ]] || { echo "Cannot read $FILE" >&2; exit 1; }

echo "About to restore: $FILE"
echo "Into:             ${DB_NAME:-blockharbor} (as ${DB_MIGRATOR_USER:-blockharbor_migrator})"
echo "Warning: this will DROP all existing tables and replace with backup contents."

if [[ $FORCE -eq 0 ]]; then
    read -r -p "Type 'restore' to confirm: " ans
    [[ "$ans" == "restore" ]] || { echo "Aborted."; exit 0; }
fi

# Decrypt if .gpg
if [[ "$FILE" == *.gpg ]]; then
    TMP=$(mktemp)
    trap 'rm -f "$TMP"' EXIT
    gpg --decrypt --batch --output "$TMP" "$FILE"
    FILE="$TMP"
fi

# Drop + recreate schema (clean slate)
PGPASSWORD="$DB_MIGRATOR_PASSWORD" psql \
    -h "${DB_HOST:-127.0.0.1}" \
    -U "${DB_MIGRATOR_USER:-blockharbor_migrator}" \
    -d "${DB_NAME:-blockharbor}" <<SQL
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO ${DB_MIGRATOR_USER:-blockharbor_migrator};
GRANT USAGE ON SCHEMA public TO ${DB_USER:-blockharbor_app};
SQL

PGPASSWORD="$DB_MIGRATOR_PASSWORD" pg_restore \
    -h "${DB_HOST:-127.0.0.1}" \
    -U "${DB_MIGRATOR_USER:-blockharbor_migrator}" \
    -d "${DB_NAME:-blockharbor}" \
    --no-owner --no-acl \
    --exit-on-error \
    "$FILE"

echo "Restore complete."

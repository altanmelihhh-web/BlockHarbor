#!/usr/bin/env bash
#
# BlockHarbor — backup
#
# Creates pg_dump --format=custom + optional GPG encryption.
# Writes to ${BACKUP_DIR:-/var/backups/blockharbor}/blockharbor-<ts>.pgdump[.gpg]
#
# Usage:
#   sudo bash bin/backup.sh                 # plain pg_dump (custom format)
#   sudo bash bin/backup.sh --gpg <key-id>  # encrypt to given GPG key
#   sudo bash bin/backup.sh --quiet         # only error output

set -Eeuo pipefail

GPG_KEY=""
QUIET=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --gpg)   GPG_KEY="$2"; shift 2 ;;
        --quiet) QUIET=1; shift ;;
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 2 ;;
    esac
done

INSTALL_DIR="${INSTALL_DIR:-/var/www/blockharbor}"
ENV_FILE="$INSTALL_DIR/.env"
[[ -r "$ENV_FILE" ]] || { echo "Cannot read $ENV_FILE" >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a

BACKUP_DIR="${BACKUP_DIR:-/var/backups/blockharbor}"
mkdir -p "$BACKUP_DIR"

TS=$(date +%Y%m%d-%H%M%S)
OUT="$BACKUP_DIR/blockharbor-$TS.pgdump"

log() { [[ $QUIET -eq 0 ]] && printf '\e[1;34m[backup]\e[0m %s\n' "$*"; }

log "Running pg_dump → $OUT"
PGPASSWORD="$DB_PASSWORD" pg_dump \
    -h "${DB_HOST:-127.0.0.1}" \
    -U "${DB_USER:-blockharbor_app}" \
    -d "${DB_NAME:-blockharbor}" \
    --format=custom \
    --no-owner \
    --no-acl \
    -f "$OUT"

SIZE=$(stat -c %s "$OUT")
log "pg_dump complete: $((SIZE / 1024)) KB"

if [[ -n "$GPG_KEY" ]]; then
    log "Encrypting with GPG key $GPG_KEY"
    gpg --batch --yes --recipient "$GPG_KEY" --encrypt --output "$OUT.gpg" "$OUT"
    rm -f "$OUT"
    OUT="$OUT.gpg"
    log "Encrypted output: $OUT"
fi

chmod 600 "$OUT"
chown www-data:www-data "$OUT"
log "Done: $OUT"
echo "$OUT"

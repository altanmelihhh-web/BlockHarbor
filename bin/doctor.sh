#!/usr/bin/env bash
#
# BlockHarbor — health check (doctor)
# Exit codes: 0 = all green; 1 = at least one failure
#
# Usage:
#   bash bin/doctor.sh             # color report
#   bash bin/doctor.sh --quiet     # only failures
#   bash bin/doctor.sh --json      # JSON output (for monitoring)

set -uo pipefail

QUIET=0
JSON=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quiet) QUIET=1; shift ;;
        --json)  JSON=1; QUIET=1; shift ;;
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 2 ;;
    esac
done

INSTALL_DIR="${INSTALL_DIR:-/var/www/blockharbor}"
ENV_FILE="$INSTALL_DIR/.env"
declare -A RESULTS

red()    { printf '\e[1;31m%s\e[0m' "$*"; }
green()  { printf '\e[1;32m%s\e[0m' "$*"; }
yellow() { printf '\e[1;33m%s\e[0m' "$*"; }

check() {
    local name="$1" status="$2" detail="$3"
    RESULTS[$name]="$status|$detail"
    if [[ $JSON -eq 0 && ( $QUIET -eq 0 || "$status" != "OK" ) ]]; then
        case "$status" in
            OK)   printf '  [%s] %-30s %s\n' "$(green ✓)" "$name" "$detail" ;;
            WARN) printf '  [%s] %-30s %s\n' "$(yellow ⚠)" "$name" "$detail" ;;
            FAIL) printf '  [%s] %-30s %s\n' "$(red ✗)" "$name" "$detail" ;;
        esac
    fi
}

# 1. Install dir exists
[[ -d "$INSTALL_DIR" ]] \
    && check "install_dir" OK   "$INSTALL_DIR" \
    || check "install_dir" FAIL "$INSTALL_DIR missing"

# 2. .env exists + readable + mode 600
if [[ -r "$ENV_FILE" ]]; then
    PERM=$(stat -c %a "$ENV_FILE")
    [[ "$PERM" == "600" ]] \
        && check "env_file" OK   "mode 600" \
        || check "env_file" WARN "mode $PERM (should be 600)"
    set -a; . "$ENV_FILE" 2>/dev/null || true; set +a
else
    check "env_file" FAIL ".env missing or unreadable"
fi

# 3. PG reachable
if command -v psql >/dev/null && [[ -n "${DB_PASSWORD:-}" ]]; then
    if PGPASSWORD="$DB_PASSWORD" psql -h "${DB_HOST:-127.0.0.1}" -U "${DB_USER:-blockharbor_app}" \
            -d "${DB_NAME:-blockharbor}" -tAc "SELECT 1" 2>/dev/null | grep -q 1; then
        check "db_connect" OK "$DB_USER@$DB_HOST/$DB_NAME"
    else
        check "db_connect" FAIL "auth or network failure"
    fi
else
    check "db_connect" WARN "skipped (no psql or DB_PASSWORD)"
fi

# 4. Migrations applied
if [[ -d "$INSTALL_DIR/db/migrations" ]] && [[ -x "$INSTALL_DIR/vendor/bin/phinx" ]]; then
    PENDING=$(cd "$INSTALL_DIR" && vendor/bin/phinx status 2>/dev/null | grep -c '^\s*down')
    if [[ "$PENDING" == "0" ]]; then
        check "migrations" OK "all applied"
    else
        check "migrations" WARN "$PENDING pending — run vendor/bin/phinx migrate"
    fi
else
    check "migrations" WARN "phinx not installed yet"
fi

# 5. Apache running + vhost enabled
if systemctl is-active apache2 >/dev/null 2>&1; then
    if [[ -L /etc/apache2/sites-enabled/blockharbor.conf ]]; then
        check "apache_vhost" OK "blockharbor.conf enabled"
    else
        check "apache_vhost" FAIL "vhost not enabled (run: sudo a2ensite blockharbor)"
    fi
else
    check "apache_vhost" FAIL "apache2 not running"
fi

# 6. Log directory writable
if [[ -d /var/log/blockharbor ]] && [[ -w /var/log/blockharbor ]]; then
    check "log_dir" OK "/var/log/blockharbor writable"
else
    check "log_dir" FAIL "/var/log/blockharbor missing or not writable"
fi

# 7. Backup directory exists
[[ -d /var/backups/blockharbor ]] \
    && check "backup_dir" OK "/var/backups/blockharbor" \
    || check "backup_dir" WARN "/var/backups/blockharbor missing (run bin/install.sh)"

# 8. Cron registered
if [[ -f /etc/cron.d/blockharbor ]]; then
    REGISTERED=$(grep -c '^[^#]' /etc/cron.d/blockharbor 2>/dev/null || echo 0)
    check "cron" OK "$REGISTERED entry/entries active"
else
    check "cron" WARN "no /etc/cron.d/blockharbor"
fi

# 9. Disk space at /var
FREE_MB=$(df -BM /var | tail -1 | awk '{print $4}' | tr -d 'M')
if (( FREE_MB > 1024 )); then
    check "disk_var" OK "${FREE_MB} MB free"
elif (( FREE_MB > 200 )); then
    check "disk_var" WARN "${FREE_MB} MB free (low)"
else
    check "disk_var" FAIL "${FREE_MB} MB free (critical)"
fi

# 10. TLS cert expiry (if vhost present)
VHOST=/etc/apache2/sites-available/blockharbor.conf
if [[ -r "$VHOST" ]]; then
    CERT=$(awk '/SSLCertificateFile/ {print $2}' "$VHOST" | head -1)
    if [[ -r "$CERT" ]]; then
        EXPIRY_EPOCH=$(date -d "$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)" +%s 2>/dev/null || echo 0)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
        if   (( DAYS_LEFT > 30 )); then check "tls_cert" OK "expires in $DAYS_LEFT days"
        elif (( DAYS_LEFT > 7 ));  then check "tls_cert" WARN "expires in $DAYS_LEFT days"
        else                            check "tls_cert" FAIL "expires in $DAYS_LEFT days"
        fi
    else
        check "tls_cert" WARN "cert path not readable"
    fi
fi

# 11. Audit chain integrity (if verifier exists)
if [[ -x "$INSTALL_DIR/bin/verify-audit-chain" ]]; then
    if "$INSTALL_DIR/bin/verify-audit-chain" --quiet 2>/dev/null; then
        check "audit_chain" OK "no tamper detected"
    else
        check "audit_chain" FAIL "chain mismatch — investigate!"
    fi
fi

# 12. Composer + npm installed
[[ -d "$INSTALL_DIR/vendor" ]] \
    && check "composer_deps" OK "vendor/ present" \
    || check "composer_deps" WARN "run composer install"

# Output
if [[ $JSON -eq 1 ]]; then
    printf '{'
    first=1
    for k in "${!RESULTS[@]}"; do
        [[ $first -eq 0 ]] && printf ','
        IFS='|' read -r status detail <<< "${RESULTS[$k]}"
        printf '"%s":{"status":"%s","detail":"%s"}' "$k" "$status" "$detail"
        first=0
    done
    printf '}\n'
fi

FAILS=0
for k in "${!RESULTS[@]}"; do
    IFS='|' read -r status _ <<< "${RESULTS[$k]}"
    [[ "$status" == "FAIL" ]] && ((FAILS++))
done

if [[ $JSON -eq 0 ]]; then
    echo
    if (( FAILS == 0 )); then
        echo "$(green '✓ All checks passed.')"
    else
        echo "$(red "✗ $FAILS check(s) failed.")"
    fi
fi

(( FAILS == 0 ))

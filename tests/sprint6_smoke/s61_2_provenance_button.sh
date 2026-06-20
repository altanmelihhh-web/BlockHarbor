#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa_tmp=$(mktemp); trap 'rm -f $COOKIES $_spa_tmp' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# Load admin SPA
curl -sk -b $COOKIES -o "$_spa_tmp" "$BASE/cyberwebeyeosblacklistadmin.php"

# The string `ioc-prov-btn` must appear at least twice:
# (1) inside SPRINT6-A3 (modal) — pre-existing
# (2) inside blacklist row template — added by this fix
count=$(grep -c "ioc-prov-btn" "$_spa_tmp" || true)
[ "$count" -ge 2 ] || { echo "FAIL: ioc-prov-btn not in row template (count=$count, expected >=2)"; exit 1; }

# Also: a `data-ip=` attribute must be present in row
grep -q "data-ip=" "$_spa_tmp" || { echo "FAIL: no data-ip= attribute"; exit 1; }

echo "PASS: s61_2_provenance_button"

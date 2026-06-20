#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); trap 'rm -f $COOKIES' EXIT

# Login as admin
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# 1. Admin can save
resp=$(curl -sk -b $COOKIES -X POST "$BASE/vendor_watchlist_save.php" \
    -d "vendors=cisco,fortinet,paloalto&min_cvss=8.0&auto_dismiss_days=30&include_kev_always=1")
echo "$resp" | grep -q '"ok":true' || { echo "FAIL: admin save (got: $resp)"; exit 1; }

# 2. JSON file actually updated
cvss=$(jq -r '.min_cvss' vendor_watchlist.json)
[ "$cvss" = "8" ] || { echo "FAIL: min_cvss not 8.0 (got $cvss)"; exit 1; }

# 3. Viewer must be denied (anon=no session)
resp_anon=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE/vendor_watchlist_save.php" -d "vendors=cisco")
[ "$resp_anon" = "302" ] || [ "$resp_anon" = "401" ] || [ "$resp_anon" = "403" ] || \
    { echo "FAIL: anon access not blocked (got $resp_anon)"; exit 1; }

# 4. UI section present in admin SPA
_spa_tmp=$(mktemp)
curl -sk -b $COOKIES "$BASE/cyberwebeyeosblacklistadmin.php" -o "$_spa_tmp"
grep -q "SPRINT6-A5" "$_spa_tmp" || { rm -f "$_spa_tmp"; echo "FAIL: SPRINT6-A5 marker missing in admin SPA"; exit 1; }
rm -f "$_spa_tmp"

# Restore original watchlist (so test is re-runnable)
cat > vendor_watchlist.json <<'EOF'
{
    "vendors": ["cisco","fortinet","microsoft","vmware","apache","palo alto","checkpoint","f5","citrix","linux"],
    "min_cvss": 7.0,
    "auto_dismiss_days": 30,
    "include_kev_always": true,
    "fetch_window_days": 7
}
EOF

echo "PASS: t2_watchlist_ui"

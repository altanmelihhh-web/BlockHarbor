#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); trap 'rm -f $COOKIES' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# 1. List action: returns JSON with items[] and count
resp=$(curl -sk -b $COOKIES "$BASE/cve_action.php?action=list")
echo "$resp" | jq -e '.items | type == "array"' >/dev/null || { echo "FAIL: list not array (got: $(echo "$resp" | head -c 200))"; exit 1; }
echo "$resp" | jq -e 'has("count")' >/dev/null || { echo "FAIL: count missing"; exit 1; }

# 2. Stats action
stats=$(curl -sk -b $COOKIES "$BASE/cve_action.php?action=stats")
echo "$stats" | jq -e 'has("kev_count") and has("epss_high_count")' >/dev/null || { echo "FAIL: stats malformed"; exit 1; }

# 3. UI marker present
_spa_tmp=$(mktemp); trap 'rm -f $COOKIES $_spa_tmp' EXIT
curl -sk -b $COOKIES -o "$_spa_tmp" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "SPRINT6-A1" "$_spa_tmp" || { echo "FAIL: SPRINT6-A1 marker missing"; exit 1; }

# 4. Dismiss requires POST + valid CVE
fake_cve="CVE-9999-99999"
dismiss=$(curl -sk -b $COOKIES -X POST "$BASE/cve_action.php?action=dismiss" -d "cve=$fake_cve")
echo "$dismiss" | jq -e '.ok' >/dev/null || { echo "FAIL: dismiss endpoint broken (got: $dismiss)"; exit 1; }

# 5. Anon blocked
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/cve_action.php?action=list")
[ "$code" = "302" ] || [ "$code" = "401" ] || [ "$code" = "403" ] || \
    { echo "FAIL: anon allowed (got $code)"; exit 1; }

# 6. Cleanup dismiss state (re-runnability)
if [ -f cve_action_dismiss.json ]; then
    php -r '$f="cve_action_dismiss.json"; $d=json_decode(file_get_contents($f),true)?:[]; unset($d["CVE-9999-99999"]); file_put_contents($f, json_encode($d, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));'
fi

echo "PASS: t3_action_required"

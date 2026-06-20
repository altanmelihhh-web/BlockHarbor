#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa_tmp=$(mktemp); trap 'rm -f $COOKIES $_spa_tmp' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# 1. Lookup endpoint returns combined shape (greynoise+threatfox+shodan stubs)
resp=$(curl -sk -b $COOKIES "$BASE/ioc_pivot.php?action=lookup&cve=CVE-2024-3400")
echo "$resp" | jq -e '.candidates | type == "array"' >/dev/null || { echo "FAIL: candidates not array (got: $(echo "$resp" | head -c 200))"; exit 1; }
echo "$resp" | jq -e 'has("sources")' >/dev/null || { echo "FAIL: sources missing"; exit 1; }

# 2. Backup blacklist.txt before add test
cp blacklist.txt /tmp/sprint6_t6_bl_bak

# 3. Add endpoint requires POST with valid CVE + ips[]
add=$(curl -sk -b $COOKIES -X POST "$BASE/ioc_pivot.php?action=add" \
  -d 'cve=CVE-2024-3400' \
  -d 'ips[]=203.0.113.99' \
  -d 'ttl_days=14' \
  -d 'confidence=70')
echo "$add" | jq -e '.ok and (.added | type == "number")' >/dev/null || { echo "FAIL: add response (got: $add)"; exit 1; }
grep -q "^203\.0\.113\.99|" blacklist.txt || { echo "FAIL: 203.0.113.99 not in blacklist.txt"; exit 1; }

# 4. Cleanup test IP
cp /tmp/sprint6_t6_bl_bak blacklist.txt
# Cleanup meta entry
if [ -f blacklist_meta.json ]; then
    php -r '$f="blacklist_meta.json"; $m=json_decode(file_get_contents($f),true)?:[]; unset($m["203.0.113.99"]); file_put_contents($f, json_encode($m, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));'
fi

# 5. UI marker present
curl -sk -b $COOKIES -o "$_spa_tmp" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "SPRINT6-A2" "$_spa_tmp" || { echo "FAIL: SPRINT6-A2 marker missing"; exit 1; }

echo "PASS: t6_ioc_pivot"

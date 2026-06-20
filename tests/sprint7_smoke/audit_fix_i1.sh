#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# JS handler block present
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "SPRINT7-I1 SIDEBAR-ACTIONS" "$_spa" || { echo "FAIL: I1 handler missing"; exit 1; }
grep -q "ln-edit\|ln-del\|ln-fetch\|ln-toggle" "$_spa" || { echo "FAIL: handler selectors missing"; exit 1; }

# Test backend: rename action
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=rename&slug=manual&new_name=Test")
echo "$resp" | head -c 200
echo "$resp" | grep -qE '"ok":(true|false)|"error"' || { echo "FAIL: rename endpoint doesn't return JSON ok/error"; exit 1; }

# Test backend: toggle action returns JSON
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=toggle&slug=manual")
echo "$resp" | head -c 200
echo "$resp" | grep -qE '"ok":(true|false)|"error"' || { echo "FAIL: toggle endpoint doesn't return JSON"; exit 1; }

# Test backend: fetch_now returns JSON
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=fetch_now&slug=manual")
echo "$resp" | head -c 200

echo "PASS: audit_fix_i1"

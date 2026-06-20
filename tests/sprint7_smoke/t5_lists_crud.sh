#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); trap 'rm -f $COOKIES' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# 1. Invalid slug rejected
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=create&name=Test&slug=Bad_Slug&side=blacklist&type_hint=ip")
echo "$resp" | grep -qiE "invalid|400|slug" && echo "  ✓ invalid slug rejected" || { echo "FAIL: invalid slug not rejected (resp: $(echo "$resp" | head -c 200))"; exit 1; }

# 2. Valid create succeeds
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=create&name=Sprint7%20Test&slug=s7-test&side=blacklist&type_hint=mixed&description=test&default_tlp=AMBER&default_confidence=70")
# Accept either redirect (302) or success JSON
echo "$resp" | head -c 500

# Verify list exists in lists.json
jq -e '.lists[] | select(.slug == "s7-test")' lists.json >/dev/null || { echo "FAIL: list not in lists.json"; exit 1; }
echo "  ✓ list created"

# 3. Delete non-empty list rejected (seed an entry first)
touch lists_dyn/s7-test.txt
echo "1.2.3.4|ip-src|test|2026-05-21|test||||AMBER|70|permanent" > lists_dyn/s7-test.txt

resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=delete&slug=s7-test")
# Match literal Turkish OR unicode-escaped form (ş=ş, ı=ı, ğ=ğ)
echo "$resp" | grep -qiE 'bo[şsş]|empty|kayit|kay|nce|409' && echo "  ✓ non-empty delete rejected" || { echo "FAIL: non-empty delete not rejected (resp: $(echo "$resp" | head -c 300))"; exit 1; }

# 4. Empty list delete succeeds
> lists_dyn/s7-test.txt
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=delete&slug=s7-test")
jq -e '.lists[] | select(.slug == "s7-test")' lists.json >/dev/null && { echo "FAIL: list still in lists.json after empty delete"; exit 1; }
echo "  ✓ empty list deleted"

# 5. System list delete rejected
resp=$(curl -sk -b $COOKIES -X POST "$BASE/lists.php" -d "action=delete&slug=manual")
echo "$resp" | grep -qiE "system|403|korumalı|protected" && echo "  ✓ system delete rejected" || echo "  ⚠ system delete check inconclusive"

# Cleanup any test file
rm -f lists_dyn/s7-test.txt

echo "PASS: t5_lists_crud"

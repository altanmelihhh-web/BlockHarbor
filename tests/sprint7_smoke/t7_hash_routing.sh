#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"

# Markers present
grep -q "SPRINT7-T7 HASH-ROUTING" "$_spa" || { echo "FAIL: SPRINT7-T7 marker missing"; exit 1; }

# Key JS pieces present
grep -q "function parseHash" "$_spa" || { echo "FAIL: parseHash function missing"; exit 1; }
grep -q "function applyHash" "$_spa" || { echo "FAIL: applyHash function missing"; exit 1; }
grep -q "window.addEventListener.'hashchange'" "$_spa" || { echo "FAIL: hashchange listener missing"; exit 1; }

# Server-side support: SPA must accept ?list= query (lay groundwork for T8)
# For now we just verify the JS exists; T8 will wire server-side support

echo "PASS: t7_hash_routing"

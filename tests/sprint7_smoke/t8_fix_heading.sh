#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# Default view — heading shows "Tüm Manuel Kayıtlar"
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "Tüm Manuel Kayıtlar" "$_spa" || { echo "FAIL: default heading not 'Tüm Manuel Kayıtlar'"; exit 1; }
grep -q "Kara Liste — Manuel + Birleşik" "$_spa" && { echo "FAIL: old hardcoded heading still present"; exit 1; } || true

# USOM list view — heading shows "USOM TR-CERT (domain)"
USOM_SLUG=$(jq -r '.lists[] | select(.name | test("USOM"; "i")) | .slug' lists.json | head -1)
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=$USOM_SLUG"
grep -q "USOM TR-CERT (domain)" "$_spa" || { echo "FAIL: USOM heading missing"; exit 1; }
grep -q "🌍 Dış Kaynak" "$_spa" || { echo "FAIL: kind label '🌍 Dış Kaynak' missing"; exit 1; }

# JS click handler present
grep -q "Sidebar link click → navigate directly" "$_spa" || { echo "FAIL: sidebar click handler missing"; exit 1; }

echo "PASS: t8_fix_heading"

#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"

# Markers present
grep -q "SPRINT7-T6 SIDEBAR" "$_spa" || { echo "FAIL: SPRINT7-T6 marker missing"; exit 1; }
grep -q 'class="listnav"' "$_spa" || { echo "FAIL: .listnav class missing"; exit 1; }
grep -q "Manuel Listeler" "$_spa" || { echo "FAIL: Manuel Listeler heading missing"; exit 1; }
grep -q "Dış Kaynaklar" "$_spa" || { echo "FAIL: Dış Kaynaklar heading missing"; exit 1; }
grep -q "Akıllı Listeler" "$_spa" || { echo "FAIL: Akıllı Listeler heading missing"; exit 1; }
grep -q "main-grid--with-listnav" "$_spa" || { echo "FAIL: main-grid--with-listnav class missing"; exit 1; }

# At least 1 list item rendered (external feeds from T4 migration)
grep -c '<li data-slug=' "$_spa" | awk '{ if ($1 < 2) { print "FAIL: expected >=2 sidebar items, got " $1; exit 1 } }'

echo "PASS: t6_sidebar"

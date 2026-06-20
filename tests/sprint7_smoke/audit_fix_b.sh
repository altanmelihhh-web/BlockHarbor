#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# Tümü Dış Kaynak item present in sidebar
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "Tümü Dış Kaynak" "$_spa" || { echo "FAIL: Tümü Dış Kaynak item missing"; exit 1; }

# all-external view renders summary, not full data
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=all-external"
grep -q "USOM TR-CERT" "$_spa" || { echo "FAIL: external summary missing USOM"; exit 1; }

# USOM list view — must respond fast (< 5s) — measure
USOM_SLUG=$(jq -r '.lists[] | select(.name | test("USOM"; "i")) | .slug' lists.json | head -1)
start=$(date +%s%N)
curl -sk -b $COOKIES -o /dev/null "$BASE/cyberwebeyeosblacklistadmin.php?list=$USOM_SLUG"
end=$(date +%s%N)
duration_ms=$(( (end - start) / 1000000 ))
echo "USOM page load: ${duration_ms}ms"
[ $duration_ms -lt 5000 ] || { echo "FAIL: USOM load >5s ($duration_ms ms)"; exit 1; }

echo "PASS: audit_fix_b"

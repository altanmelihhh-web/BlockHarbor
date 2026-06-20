#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"

# New compact dropdown present
grep -q 'id="bl-qfilter"' "$_spa" || { echo "FAIL: bl-qfilter dropdown missing"; exit 1; }
grep -q "🆕 Bu hafta eklenenler" "$_spa" || { echo "FAIL: 'Bu hafta eklenenler' option missing"; exit 1; }

# Old KPI bar + chips REMOVED
grep -q "📊 Toplam" "$_spa" && { echo "FAIL: old KPI bar still present"; exit 1; } || true
grep -q "bl-qfchip" "$_spa" && { echo "FAIL: old chip class still present"; exit 1; } || true
grep -q "Yüksek Öncelikli</button>" "$_spa" && { echo "FAIL: chip button still present"; exit 1; } || true

# Filter is much shorter (single line)
grep -c "bl-qfilter-wrap\|bl-qfilter\b" "$_spa" | awk '{ if ($1 < 2) { print "FAIL: filter wrap or select missing"; exit 1 } }'

echo "PASS: t7_6_compact_filter"

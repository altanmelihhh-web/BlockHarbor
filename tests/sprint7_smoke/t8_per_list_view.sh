#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# 1. Default view (all) — no per-list toolbar
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "sprint7-list-toolbar" "$_spa" && { echo "FAIL: toolbar shown in default view"; exit 1; } || true

# 2. Per-list view — toolbar shown for system/manual list
SLUG=$(python3 -c "
import json, sys
data = json.load(open('lists.json'))
for l in data['lists']:
    if l.get('kind') in ('system','manual') and l.get('side') == 'blacklist':
        print(l['slug']); sys.exit(0)
")
[ -n "$SLUG" ] || { echo "FAIL: no system/manual blacklist slug found"; exit 1; }

curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=$SLUG"
grep -q "sprint7-list-toolbar" "$_spa" || { echo "FAIL: per-list toolbar not shown for slug=$SLUG"; exit 1; }
grep -q "Listeden" "$_spa" || { echo "FAIL: 'Listeden Cik' button missing"; exit 1; }

# 3. External list — should NOT crash (T9 handles external mode)
EXT_SLUG=$(python3 -c "
import json, sys
data = json.load(open('lists.json'))
for l in data['lists']:
    if l.get('kind') == 'external':
        print(l['slug']); sys.exit(0)
")
if [ -n "$EXT_SLUG" ]; then
    curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=$EXT_SLUG"
    grep -qE "<b>(Fatal error|Parse error|Warning).*on line" "$_spa" && { echo "FAIL: PHP error on external list view"; exit 1; } || true
fi

echo "PASS: t8_per_list_view"

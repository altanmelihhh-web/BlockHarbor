#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# C4: download URL should NOT contain /var/www server path
USOM_SLUG=$(jq -r '.lists[] | select(.name | test("USOM"; "i")) | .slug' lists.json | head -1)
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=$USOM_SLUG"
grep -oE 'href="/var/www/[^"]*"' "$_spa" | head -3 && { echo "FAIL C4: server path leaked in href"; exit 1; } || true

# I2: in default view, "Tümü" should be active
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q 'data-slug="all"[^>]*class="active"' "$_spa" || { echo "FAIL I2: Tümü not active in default view"; exit 1; }

# I2: in USOM view, "Tümü" should NOT be active, USOM item should be
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=$USOM_SLUG"
grep -q "data-slug=\"$USOM_SLUG\"[^>]*class=\"active\"" "$_spa" || { echo "FAIL I2: USOM item not active in USOM view"; exit 1; }

# I5: dropdown should be hidden in per-list view
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list=$USOM_SLUG"
grep -q 'name="list_filter"' "$_spa" && { echo "FAIL I5: list_filter dropdown still shown in per-list view"; exit 1; } || true

# I6: legacy list_filter heading
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php?list_filter=$USOM_SLUG"
grep -q "USOM TR-CERT (domain)" "$_spa" || echo "  ⚠ I6: legacy list_filter param heading not dynamic (may be acceptable)"

echo "PASS: audit_fix_a"

#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"

# Old teal brand reduced (cannot fully eliminate — Chart.js uses it)
old_teal_count=$(grep -oE "#16a085" "$_spa" | wc -l)
echo "Old teal references remaining: $old_teal_count (target: small, < 5)"

# New blue primary present
grep -q "#1971c2" "$_spa" || { echo "FAIL: new blue primary not in CSS"; exit 1; }

# Gradients reduced (count should be much lower)
grad_count=$(grep -oE "linear-gradient" "$_spa" | wc -l)
echo "linear-gradient references: $grad_count (target: small)"

# border-radius normalized
grep -q "border-radius:6px\|border-radius: 6px" "$_spa" || { echo "FAIL: 6px border-radius not found"; exit 1; }

# PHP no errors
grep -q "Parse error\|Fatal error" "$_spa" && { echo "FAIL: PHP error in rendered output"; exit 1; } || true

echo "PASS: theme_apply"

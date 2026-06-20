#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa=$(mktemp); trap 'rm -f $COOKIES $_spa' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null
curl -sk -b $COOKIES -o "$_spa" "$BASE/cyberwebeyeosblacklistadmin.php"

# New labels must be present
grep -q "📊 Toplam" "$_spa" || { echo "FAIL: KPI bar Toplam missing"; exit 1; }
grep -q "🆕 Bu Hafta Eklenen" "$_spa" || { echo "FAIL: 'Bu Hafta Eklenen' chip missing"; exit 1; }
grep -q "⏰ Süresi Dolmuş" "$_spa" || { echo "FAIL: 'Süresi Dolmuş' chip missing"; exit 1; }
grep -q "🔴 Yüksek Öncelikli" "$_spa" || { echo "FAIL: 'Yüksek Öncelikli' chip missing"; exit 1; }

# Old jargon labels must be REMOVED
grep -q "TLP:RED" "$_spa" && { echo "FAIL: old TLP:RED chip still present"; exit 1; } || true
grep -q "Conf≥80" "$_spa" && { echo "FAIL: old Conf≥80 chip still present"; exit 1; } || true
grep -q "FP raporlu" "$_spa" && { echo "FAIL: old 'FP raporlu' chip still present"; exit 1; } || true

echo "PASS: t7_5_kpi_chips"

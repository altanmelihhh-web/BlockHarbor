#!/usr/bin/env bash
set -uo pipefail
cd /var/www/html/tests/sprint6_smoke
fails=0
total=0
echo "=== Sprint 6 Smoke Test Suite ==="
for t in t1_feed_health.sh t2_watchlist_ui.sh t3_action_required.sh \
         t4_greynoise.sh t5_threatfox.sh t6_ioc_pivot.sh t7_provenance.sh \
         t8_ttl_expiry.sh t9_shodan.sh t10_csaf.sh t11_psirt_rss.sh; do
    total=$((total+1))
    if bash "$t" >/dev/null 2>&1; then
        echo "  ✓ $t"
    else
        echo "  ✗ $t"
        # Re-run with full output for diagnostics
        echo "    --- diagnostic output ---"
        bash "$t" 2>&1 | tail -10 | sed 's/^/    /'
        fails=$((fails+1))
    fi
done
echo "==="
echo "Results: $((total-fails))/$total PASS, $fails FAIL"
exit $fails

<?php
/**
 * Cyberwebeyeos — Audit Log Hash Chain Verifier (R47 T5.2)
 *
 * CLI: php verify_audit.php [--quiet]
 *
 * Çıkış kodu:
 *   0 — chain OK (veya legacy log, prefix öncesi)
 *   1 — chain bozuk (tamper / corruption)
 *   2 — dosya yok
 */

require_once __DIR__ . '/audit_log.php';

$QUIET = in_array('--quiet', $argv, true) || in_array('-q', $argv, true);

if (!file_exists(AUDIT_LOG_FILE)) {
    if (!$QUIET) fwrite(STDERR, "audit.log yok\n");
    exit(2);
}

$r = audit_log_verify_chain();

if (!$QUIET) {
    echo "Lines verified : {$r['verified']}\n";
    echo "Legacy skipped : {$r['legacy_skipped']} (pre-T5.2 unprefixed)\n";
    if (isset($r['last_hash'])) echo "Last hash      : {$r['last_hash']}\n";
}

if (!$r['ok']) {
    if (!$QUIET) {
        echo "\n❌ CHAIN BROKEN\n";
        echo "First break at line {$r['first_break']['line']}:\n";
        if (isset($r['first_break']['reason'])) echo "  Reason: {$r['first_break']['reason']}\n";
        if (isset($r['first_break']['expected'])) {
            echo "  Expected: {$r['first_break']['expected']}\n";
            echo "  Actual  : {$r['first_break']['actual']}\n";
            echo "  Preview : {$r['first_break']['json_preview']}\n";
        }
    } else {
        fwrite(STDERR, "AUDIT CHAIN BROKEN at line {$r['first_break']['line']}\n");
    }
    exit(1);
}

if (!$QUIET) echo "\n✅ Chain verified\n";
exit(0);

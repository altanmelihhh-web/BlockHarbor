<?php
/**
 * Cyberwebeyeos — Audit Log Hash Chain Verifier (R47 T5.2)
 *
 * CLI: php verify_audit.php [--quiet]
 *   Exit codes: 0 chain OK · 1 chain broken · 2 log file missing
 *
 * Web: GET verify_audit.php        → HTML summary
 *      GET verify_audit.php?json=1 → JSON, for monitoring
 *   Requires an authenticated session; any role may read the result.
 *
 * The script previously assumed CLI unconditionally and dereferenced $argv,
 * which is undefined under a web SAPI — requesting it over HTTP raised a
 * TypeError instead of reporting the chain state.
 */

$IS_CLI = (PHP_SAPI === 'cli');

if (!$IS_CLI) {
    require_once __DIR__ . '/blacklist_admin_auth.php';
    require_role(['admin', 'operator', 'viewer']);
}

require_once __DIR__ . '/audit_log.php';

$QUIET = $IS_CLI && (in_array('--quiet', $argv ?? [], true) || in_array('-q', $argv ?? [], true));
$AS_JSON = !$IS_CLI && isset($_GET['json']);

// ---------------------------------------------------------------- log missing --

if (!file_exists(AUDIT_LOG_FILE)) {
    if ($IS_CLI) {
        if (!$QUIET) fwrite(STDERR, "audit.log yok\n");
        exit(2);
    }
    if ($AS_JSON) {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'audit_log_missing']);
        exit;
    }
    http_response_code(404);
    echo '<!doctype html><meta charset="utf-8"><title>Audit chain</title>'
       . '<p style="font:15px system-ui;margin:2rem">Audit log not found yet — '
       . 'it is created on the first audited action.</p>';
    exit;
}

$r = audit_log_verify_chain();

// ----------------------------------------------------------------------- CLI --

if ($IS_CLI) {
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
}

// ----------------------------------------------------------------------- web --

if ($AS_JSON) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($r['ok'] ? 200 : 409);
    echo json_encode($r, JSON_UNESCAPED_UNICODE);
    exit;
}

$ok   = !empty($r['ok']);
$tone = $ok ? ['#065f46', '#ecfdf5', '#10b981'] : ['#7f1d1d', '#fef2f2', '#ef4444'];
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit chain verification</title></head>
<body style="margin:0;font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;background:#f8fafc">
<div style="max-width:44rem;margin:2.5rem auto;padding:0 1rem">
  <h1 style="font-size:1.35rem;margin:0 0 1rem">Audit chain verification</h1>
  <div style="border:1px solid <?= $tone[2] ?>;background:<?= $tone[1] ?>;color:<?= $tone[0] ?>;
              border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.25rem">
    <strong style="font-size:1.05rem"><?= $ok ? 'Chain verified' : 'Chain broken' ?></strong>
    <div style="margin-top:.35rem">
      <?= (int)$r['verified'] ?> lines verified ·
      <?= (int)$r['legacy_skipped'] ?> legacy lines skipped (pre-T5.2, unprefixed)
    </div>
  </div>
  <?php if (!$ok && isset($r['first_break'])): $b = $r['first_break']; ?>
  <table style="border-collapse:collapse;width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:8px">
    <tr><th style="text-align:left;padding:.6rem .8rem;border-bottom:1px solid #e2e8f0;width:9rem">First break</th>
        <td style="padding:.6rem .8rem;border-bottom:1px solid #e2e8f0">line <?= (int)$b['line'] ?></td></tr>
    <?php foreach (['reason' => 'Reason', 'expected' => 'Expected', 'actual' => 'Actual', 'json_preview' => 'Preview'] as $k => $label):
        if (!isset($b[$k])) continue; ?>
    <tr><th style="text-align:left;padding:.6rem .8rem;border-bottom:1px solid #e2e8f0"><?= $label ?></th>
        <td style="padding:.6rem .8rem;border-bottom:1px solid #e2e8f0;font-family:ui-monospace,monospace;
                   font-size:.85em;word-break:break-all"><?= htmlspecialchars((string)$b[$k]) ?></td></tr>
    <?php endforeach; ?>
  </table>
  <?php endif; ?>
  <?php if (isset($r['last_hash'])): ?>
  <p style="color:#475569;font-size:.9em">Last hash:
     <code style="word-break:break-all"><?= htmlspecialchars((string)$r['last_hash']) ?></code></p>
  <?php endif; ?>
  <p style="margin-top:1.5rem"><a href="<?= htmlspecialchars(cwe_url('audit_log.php')) ?>"
     style="color:#2563eb">&larr; Audit log</a>
     &middot; <a href="?json=1" style="color:#2563eb">JSON</a></p>
</div>
</body></html>

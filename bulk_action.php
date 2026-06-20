<?php
/**
 * Cyberwebeyeos — Bulk Operations Handler (R29 T1.4)
 *
 * POST endpoint. Yetki: admin+operator.
 * Body params:
 *   action       — delete | move_whitelist | set_tlp | set_type | set_confidence | export_csv
 *   selected_ips — array of value strings (form `selected_ips[]=...`)
 *   tlp          — RED|AMBER|GREEN|WHITE (set_tlp için)
 *   type         — ip-src|domain|...|email-src (set_type için)
 *   confidence   — 0-100 integer (set_confidence için)
 *   return_to    — redirect URL (default: admin#blacklist)
 *
 * flock ile concurrent-write koruması.
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_once __DIR__ . '/ioc_helpers.php';
require_role(['admin','operator']);

$BLACKLIST = __DIR__ . '/blacklist.txt';
$FEED = __DIR__ . '/cyberwebeyeosblacklist.txt';
$WHITELIST = __DIR__ . '/whitelist.txt';

$action = trim($_POST['action'] ?? '');
$selected = $_POST['selected_ips'] ?? [];
if (!is_array($selected)) $selected = [];
$selected = array_values(array_filter(array_map('trim', $selected), fn($s) => $s !== ''));
$selected_set = array_flip($selected);

$return_to = !empty($_POST['return_to']) ? $_POST['return_to'] : 'cyberwebeyeosblacklistadmin.php#blacklist';

function _bulk_redirect(string $url, string $msg): never {
    $_SESSION['message'] = $msg;
    header('Location: ' . $url);
    exit;
}

if (empty($selected)) {
    _bulk_redirect($return_to, "⚠️ Hiçbir IoC seçilmedi.");
}

if (!in_array($action, ['delete','move_whitelist','set_tlp','set_type','set_confidence','export_csv'], true)) {
    _bulk_redirect($return_to, "❌ Geçersiz bulk action: " . htmlspecialchars($action));
}

// Export ayrı path — read-only, dosya değiştirmez
if ($action === 'export_csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="cwe-bulk-export-' . date('Ymd-His') . '.csv"');
    echo "value,type,comment,date,tlp,confidence,valid_until,added_by\n";
    if (file_exists($BLACKLIST)) {
        foreach (file($BLACKLIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $e = cwe_parse_blacklist_entry($line);
            if (!isset($selected_set[$e['value']])) continue;
            $cells = [
                $e['value'], $e['type'], $e['comment'], $e['date'],
                $e['tlp'], $e['confidence'], $e['valid_until'], $e['added_by'],
            ];
            $row = array_map(fn($c) => '"' . str_replace('"', '""', $c) . '"', $cells);
            echo implode(',', $row) . "\n";
        }
    }
    audit_log_event('bulk_export_csv', ['count' => count($selected)]);
    exit;
}

// Action-specific param validation
$param_tlp = null; $param_type = null; $param_conf = null;
if ($action === 'set_tlp') {
    $param_tlp = strtoupper(trim($_POST['tlp'] ?? ''));
    if (!in_array($param_tlp, CWE_TLP_VALUES, true)) {
        _bulk_redirect($return_to, "❌ Geçersiz TLP: " . htmlspecialchars($param_tlp));
    }
}
if ($action === 'set_type') {
    $param_type = strtolower(trim($_POST['type'] ?? ''));
    if (!in_array($param_type, CWE_IOC_TYPES, true)) {
        _bulk_redirect($return_to, "❌ Geçersiz tip: " . htmlspecialchars($param_type));
    }
}
if ($action === 'set_confidence') {
    if (!isset($_POST['confidence']) || $_POST['confidence'] === '') {
        _bulk_redirect($return_to, "❌ Confidence değeri zorunlu.");
    }
    $param_conf = max(0, min(100, (int)$_POST['confidence']));
}

// File-mutating actions: flock + atomic rewrite
if (!file_exists($BLACKLIST)) {
    _bulk_redirect($return_to, "❌ blacklist.txt bulunamadı.");
}

$fh = fopen($BLACKLIST, 'r+');
if (!$fh || !flock($fh, LOCK_EX)) {
    if ($fh) fclose($fh);
    _bulk_redirect($return_to, "❌ Dosya kilidi alınamadı, tekrar deneyin.");
}

// Read all
$raw_lines = [];
while (($line = fgets($fh)) !== false) {
    $raw_lines[] = rtrim($line, "\r\n");
}

$kept = [];                  // satırlar (header/comment/non-selected)
$matched_entries = [];       // matched assoc array'ler
$moved_to_whitelist = [];    // move_whitelist için
$cur_user = cwe_current_user() ?: 'bulk';
$now = date('Y-m-d H:i:s');

foreach ($raw_lines as $line) {
    if ($line === '' || ltrim($line)[0] === '#') { $kept[] = $line; continue; }
    $e = cwe_parse_blacklist_entry($line);
    if (!isset($selected_set[$e['value']])) {
        $kept[] = $line;
        continue;
    }
    // Eşleşen entry — action'a göre işle
    switch ($action) {
        case 'delete':
        case 'move_whitelist':
            $matched_entries[] = $e;
            if ($action === 'move_whitelist') $moved_to_whitelist[] = $e;
            // (kept'e eklenmez → silinir)
            break;
        case 'set_tlp':
            $e['tlp'] = $param_tlp;
            $matched_entries[] = $e;
            $kept[] = cwe_format_blacklist_entry($e);
            break;
        case 'set_type':
            $e['type'] = $param_type;
            $matched_entries[] = $e;
            $kept[] = cwe_format_blacklist_entry($e);
            break;
        case 'set_confidence':
            $e['confidence'] = $param_conf;
            $matched_entries[] = $e;
            $kept[] = cwe_format_blacklist_entry($e);
            break;
    }
}

$count = count($matched_entries);
if ($count === 0) {
    flock($fh, LOCK_UN); fclose($fh);
    _bulk_redirect($return_to, "ℹ️ Seçilen IoC'lerden hiçbiri blacklist.txt'de bulunamadı (silinmiş olabilir).");
}

// Write back
ftruncate($fh, 0);
rewind($fh);
fwrite($fh, implode("\n", $kept) . (count($kept) ? "\n" : ''));
fflush($fh);
flock($fh, LOCK_UN);
fclose($fh);

// Feed (delete + move_whitelist) — feed sadece value'leri içerir; rebuild
if ($action === 'delete' || $action === 'move_whitelist') {
    $feed_vals = [];
    foreach ($kept as $line) {
        if ($line === '' || ltrim($line)[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        $feed_vals[] = $e['value'];
    }
    file_put_contents($FEED, implode("\n", $feed_vals) . (count($feed_vals) ? "\n" : ''));
}

// Move to whitelist — pipe-format: value|date|user|comment|tlp
if ($action === 'move_whitelist' && !empty($moved_to_whitelist)) {
    $wl_existing = file_exists($WHITELIST) ? file($WHITELIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $wl_have = [];
    foreach ($wl_existing as $l) {
        $wl_have[trim(explode('|', $l)[0])] = true;
    }
    $wl_append = [];
    foreach ($moved_to_whitelist as $e) {
        if (isset($wl_have[$e['value']])) continue;
        $cmt = 'bulk-moved · ' . $e['comment'];
        $wl_append[] = $e['value'] . '|' . $now . '|' . $cur_user . '|' . str_replace('|', ' ', $cmt) . '|' . $e['tlp'];
    }
    if ($wl_append) {
        file_put_contents($WHITELIST, implode("\n", $wl_append) . "\n", FILE_APPEND);
    }
}

audit_log_event('bulk_' . $action, [
    'count' => $count,
    'values_sample' => array_slice(array_map(fn($e) => $e['value'], $matched_entries), 0, 5),
    'param_tlp' => $param_tlp,
    'param_type' => $param_type,
    'param_confidence' => $param_conf,
]);

$action_label = [
    'delete'         => "🗑️ Silindi",
    'move_whitelist' => "→ Whitelist'e taşındı",
    'set_tlp'        => "TLP = {$param_tlp} atandı",
    'set_type'       => "Tip = {$param_type} atandı",
    'set_confidence' => "Confidence = {$param_conf} atandı",
][$action];

_bulk_redirect($return_to, "✅ Toplu işlem: <b>{$count}</b> IoC — {$action_label}");

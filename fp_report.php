<?php
/**
 * Cyberwebeyeos — False Positive Reporter (R32 T2.2)
 *
 * POST {value, comment, return_to}
 * Auth: admin+operator (viewer'lar FP raporlayamaz).
 *
 * Davranış:
 *   1. fp_state.json'da value için fp_count++, reports[] += {user,comment,ts}
 *   2. Source counter güncelle (entry'nin 'added_by' veya source label'i)
 *   3. fp_count >= FP_AUTO_PENDING_THRESHOLD ise blacklist'ten çıkar,
 *      pending_ips.json'a otomatik aktar (FP gerekçesiyle).
 *   4. audit log: fp_report + (gerekirse) fp_auto_pending
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_once __DIR__ . '/ioc_helpers.php';
require_role(['admin','operator']);

define('FP_STATE_FILE', __DIR__ . '/fp_state.json');
define('FP_AUTO_PENDING_THRESHOLD', 3);
define('BLACKLIST_FILE', __DIR__ . '/blacklist.txt');
define('FEED_FILE', __DIR__ . '/cyberwebeyeosblacklist.txt');
define('PENDING_FILE', __DIR__ . '/pending_ips.json');

$value = trim($_POST['value'] ?? '');
$comment = trim($_POST['comment'] ?? '');
$return_to = !empty($_POST['return_to']) ? $_POST['return_to'] : 'cyberwebeyeosblacklistadmin.php#blacklist';

if ($value === '') {
    $_SESSION['message'] = "❌ FP report: value zorunlu.";
    header('Location: ' . $return_to);
    exit;
}

$now = date('Y-m-d H:i:s');
$user = cwe_current_user() ?: 'unknown';

// --- fp_state.json güncelle (flock'lu) ---
$fh = fopen(FP_STATE_FILE, 'c+');
if (!$fh || !flock($fh, LOCK_EX)) {
    if ($fh) fclose($fh);
    $_SESSION['message'] = "❌ FP state kilidi alınamadı.";
    header('Location: ' . $return_to);
    exit;
}
$raw = stream_get_contents($fh);
$state = json_decode($raw, true);
if (!is_array($state)) $state = ['fp_state' => [], 'source_counters' => []];
if (!isset($state['fp_state'])) $state['fp_state'] = [];
if (!isset($state['source_counters'])) $state['source_counters'] = [];

if (!isset($state['fp_state'][$value])) {
    $state['fp_state'][$value] = ['fp_count' => 0, 'first_report' => $now, 'last_fp_report' => null, 'reports' => []];
}
$state['fp_state'][$value]['fp_count']++;
$state['fp_state'][$value]['last_fp_report'] = $now;
$state['fp_state'][$value]['last_seen'] = $now;
$state['fp_state'][$value]['reports'][] = ['user' => $user, 'comment' => $comment, 'ts' => $now];

// Source counter — blacklist.txt'den entry'yi bulup added_by veya source belirle
$source_label = 'manual';
if (file_exists(BLACKLIST_FILE)) {
    foreach (file(BLACKLIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        if ($e['value'] === $value) {
            $ab = $e['added_by'];
            if (str_starts_with($ab, 'api:')) $source_label = 'api';
            elseif (str_starts_with($ab, 'csv:')) $source_label = 'csv-import';
            elseif ($ab === 'legacy') $source_label = 'legacy';
            else $source_label = 'manual:' . $ab;
            break;
        }
    }
}
if (!isset($state['source_counters'][$source_label])) {
    $state['source_counters'][$source_label] = ['fp_total' => 0, 'last_fp' => null];
}
$state['source_counters'][$source_label]['fp_total']++;
$state['source_counters'][$source_label]['last_fp'] = $now;

ftruncate($fh, 0); rewind($fh);
fwrite($fh, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
fflush($fh); flock($fh, LOCK_UN); fclose($fh);

$fp_count = $state['fp_state'][$value]['fp_count'];
audit_log_event('fp_report', ['value' => $value, 'count' => $fp_count, 'source' => $source_label, 'comment' => $comment]);

// --- Threshold geçildi mi? otomatik pending'e taşı ---
$auto_pending = false;
if ($fp_count >= FP_AUTO_PENDING_THRESHOLD) {
    // Blacklist'ten kaldır + pending'e ekle
    $kept = [];
    $removed_entry = null;
    if (file_exists(BLACKLIST_FILE)) {
        $bf = fopen(BLACKLIST_FILE, 'r+');
        if ($bf && flock($bf, LOCK_EX)) {
            $lines = [];
            while (($l = fgets($bf)) !== false) $lines[] = rtrim($l, "\r\n");
            foreach ($lines as $line) {
                if ($line === '' || (isset($line[0]) && $line[0] === '#')) { $kept[] = $line; continue; }
                $e = cwe_parse_blacklist_entry($line);
                if ($e['value'] === $value && $removed_entry === null) {
                    $removed_entry = $e;
                } else {
                    $kept[] = $line;
                }
            }
            ftruncate($bf, 0); rewind($bf);
            fwrite($bf, implode("\n", $kept) . (count($kept) ? "\n" : ''));
            fflush($bf); flock($bf, LOCK_UN);
        }
        if ($bf) fclose($bf);

        // Feed dosyasını rebuild
        $feed_vals = [];
        foreach ($kept as $line) {
            if ($line === '' || $line[0] === '#') continue;
            $fe = cwe_parse_blacklist_entry($line);
            $feed_vals[] = $fe['value'];
        }
        file_put_contents(FEED_FILE, implode("\n", $feed_vals) . (count($feed_vals) ? "\n" : ''));
    }

    if ($removed_entry) {
        // pending_ips.json'a ekle
        $pending = json_decode(@file_get_contents(PENDING_FILE), true);
        if (!is_array($pending)) $pending = ['pending_ips' => []];
        if (!isset($pending['pending_ips'])) $pending['pending_ips'] = [];
        $pending['pending_ips'][] = [
            'ip'         => $value,
            'source'     => 'fp_auto:' . $source_label,
            'created_at' => $now,
            'status'     => 'pending',
            'token'      => bin2hex(random_bytes(16)),
            'reason'     => "{$fp_count} FP raporu — otomatik pending (threshold=" . FP_AUTO_PENDING_THRESHOLD . ")",
            'fp_from'    => [
                'fp_count'  => $fp_count,
                'reports'   => array_slice($state['fp_state'][$value]['reports'], -3),
                'original'  => $removed_entry,
            ],
        ];
        file_put_contents(PENDING_FILE, json_encode($pending, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        $auto_pending = true;
        audit_log_event('fp_auto_pending', ['value' => $value, 'fp_count' => $fp_count, 'source' => $source_label]);
    }
}

$msg = "🚨 FP raporu kaydedildi: <b>" . htmlspecialchars($value) . "</b> · toplam FP={$fp_count}";
if ($auto_pending) {
    $msg .= " · ⚠️ <b>OTOMATİK PENDING'E TAŞINDI</b> (threshold=" . FP_AUTO_PENDING_THRESHOLD . ")";
}
$_SESSION['message'] = $msg;
header('Location: ' . $return_to);
exit;

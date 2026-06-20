<?php
/**
 * Cyberwebeyeos — CVE Dismiss (R43 T4.3)
 *
 * POST {cve_id, note} — admin/operator dismiss eder.
 * "Etkilenmiyoruz" veya "yamalandı" gibi durumlar için.
 *
 * Otomatik dismiss (auto-archive): cve_fetch.php cron'da çalışır,
 * 30g eski + KEV değil → auto-dismiss.
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_role(['admin','operator']);

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok'=>false,'error'=>'POST required']); exit;
}

$cve_id = trim($_POST['cve_id'] ?? '');
$note = trim($_POST['note'] ?? '');
$undo = !empty($_POST['undo']);

if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve_id)) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'Invalid cve_id']); exit;
}

$STATE_FILE = __DIR__ . '/cve_state.json';
$fh = fopen($STATE_FILE, 'c+');
if (!$fh || !flock($fh, LOCK_EX)) {
    if ($fh) fclose($fh);
    http_response_code(503);
    echo json_encode(['ok'=>false,'error'=>'State lock failed']); exit;
}
$raw = stream_get_contents($fh);
$state = json_decode($raw, true);
if (!is_array($state) || !isset($state['cves'][$cve_id])) {
    flock($fh, LOCK_UN); fclose($fh);
    echo json_encode(['ok'=>false,'error'=>'CVE not found']); exit;
}

$user = cwe_current_user() ?: 'unknown';
$now = date('Y-m-d H:i:s');

if ($undo) {
    $state['cves'][$cve_id]['dismissed_at'] = null;
    $state['cves'][$cve_id]['dismissed_by'] = null;
    $state['cves'][$cve_id]['dismiss_note'] = null;
    audit_log_event('cve_undismiss', ['cve'=>$cve_id, 'user'=>$user]);
} else {
    $state['cves'][$cve_id]['dismissed_at'] = $now;
    $state['cves'][$cve_id]['dismissed_by'] = $user;
    $state['cves'][$cve_id]['dismiss_note'] = $note;
    audit_log_event('cve_dismiss', ['cve'=>$cve_id, 'user'=>$user, 'note'=>$note]);
}

ftruncate($fh, 0); rewind($fh);
fwrite($fh, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
fflush($fh); flock($fh, LOCK_UN); fclose($fh);

echo json_encode(['ok'=>true, 'cve_id'=>$cve_id, 'dismissed'=>!$undo, 'when'=>$now]);

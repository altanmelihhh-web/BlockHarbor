<?php
// SPRINT6-A3: IoC provenance read endpoint
require_once __DIR__ . '/blacklist_admin_auth.php';
require_role(['admin', 'operator', 'viewer']);
header('Content-Type: application/json');

$ip = trim($_GET['ip'] ?? '');
if ($ip === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'ip required']);
    exit;
}

$meta_file = __DIR__ . '/blacklist_meta.json';
$meta = file_exists($meta_file) ? (json_decode(file_get_contents($meta_file), true) ?: []) : [];
$row = $meta[$ip] ?? null;

if ($row && isset($row['expires_at'])) {
    $exp = strtotime($row['expires_at']);
    $row['expires_in_days'] = $exp ? max(0, round(($exp - time()) / 86400)) : null;
    $row['expired'] = $exp && $exp < time();
}

echo json_encode(['ok' => true, 'ip' => $ip, 'meta' => $row], JSON_UNESCAPED_UNICODE);

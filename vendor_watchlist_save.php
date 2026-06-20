<?php
// SPRINT6-A5: Vendor watchlist tuning POST handler
require_once __DIR__ . '/blacklist_admin_auth.php';
require_role(['admin']);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'POST required']);
    exit;
}

$vendors_raw = trim($_POST['vendors'] ?? '');
$min_cvss = isset($_POST['min_cvss']) ? (float)$_POST['min_cvss'] : 7.0;
$auto_dismiss_days = isset($_POST['auto_dismiss_days']) ? (int)$_POST['auto_dismiss_days'] : 30;
$include_kev_always = !empty($_POST['include_kev_always']);
$fetch_window_days = isset($_POST['fetch_window_days']) ? (int)$_POST['fetch_window_days'] : 7;

if ($vendors_raw === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'vendors required']);
    exit;
}

$vendors = array_values(array_filter(array_map(
    fn($v) => strtolower(trim($v)),
    explode(',', $vendors_raw)
)));

$min_cvss = max(0.0, min(10.0, $min_cvss));
$auto_dismiss_days = max(1, min(365, $auto_dismiss_days));
$fetch_window_days = max(1, min(90, $fetch_window_days));

$config = [
    'vendors' => $vendors,
    'min_cvss' => $min_cvss,
    'auto_dismiss_days' => $auto_dismiss_days,
    'include_kev_always' => $include_kev_always,
    'fetch_window_days' => $fetch_window_days,
];

$file = __DIR__ . '/vendor_watchlist.json';
$fp = fopen($file, 'c+');
if (!$fp || !flock($fp, LOCK_EX)) {
    if ($fp) fclose($fp);
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'lock_failed']);
    exit;
}
ftruncate($fp, 0);
rewind($fp);
fwrite($fp, json_encode($config, JSON_PRETTY_PRINT));
fflush($fp);
flock($fp, LOCK_UN);
fclose($fp);

if (function_exists('audit_log_event')) {
    audit_log_event('vendor_watchlist_save', array_merge(['object' => 'vendor_watchlist.json'], $config));
}

echo json_encode(['ok' => true, 'saved' => $config]);

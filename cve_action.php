<?php
// SPRINT6-A1: Action Required widget backend
// Schema deviations from plan (actual cve_state.json fields):
//   kev    -> is_kev        (bool)
//   epss   -> epss_score    (float)
//   cvss   -> cvss_score    (float)
//   vendor -> matched_vendor (string)
//   cves are nested under top-level key "cves", not root-level
//   no pre_nvd or customer_match fields (always false)
require_once __DIR__ . '/blacklist_admin_auth.php';

const ACTION_DISMISS_STATE = __DIR__ . '/cve_action_dismiss.json';
const ACTION_TOP_N = 20;
const ACTION_EPSS_THRESHOLD = 0.7;

function action_load_cves(): array {
    $f = __DIR__ . '/cve_state.json';
    if (!file_exists($f)) return [];
    $j = json_decode(file_get_contents($f), true);
    if (!is_array($j)) return [];
    // CVEs are nested under "cves" key
    return isset($j['cves']) && is_array($j['cves']) ? $j['cves'] : $j;
}

function action_load_watchlist(): array {
    $f = __DIR__ . '/vendor_watchlist.json';
    if (!file_exists($f)) return ['vendors' => [], 'min_cvss' => 7.0, 'include_kev_always' => true];
    $j = json_decode(file_get_contents($f), true);
    return is_array($j) ? $j : [];
}

function action_load_dismissed(): array {
    if (!file_exists(ACTION_DISMISS_STATE)) return [];
    $j = json_decode(file_get_contents(ACTION_DISMISS_STATE), true);
    return is_array($j) ? $j : [];
}

function action_save_dismissed(array $d): void {
    $fh = fopen(ACTION_DISMISS_STATE, 'c+');
    if (!$fh || !flock($fh, LOCK_EX)) { if ($fh) fclose($fh); return; }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
}

function action_filter(array $cves, array $watchlist, array $dismissed): array {
    $vendors = array_map('strtolower', $watchlist['vendors'] ?? []);
    $min_cvss = (float)($watchlist['min_cvss'] ?? 7.0);
    $kev_always = !empty($watchlist['include_kev_always']);
    $now = time();
    $auto_dismiss_secs = ((int)($watchlist['auto_dismiss_days'] ?? 30)) * 86400;

    $out = [];
    foreach ($cves as $id => $row) {
        if (!is_array($row)) continue;
        if (!str_starts_with($id, 'CVE-')) continue;

        // Explicit dismiss (from our dismiss state file)
        if (isset($dismissed[$id])) {
            $ts = strtotime($dismissed[$id]['at'] ?? '');
            if ($ts && ($now - $ts) < $auto_dismiss_secs) continue;
        }

        // Actual field names in cve_state.json:
        //   is_kev, epss_score, cvss_score, matched_vendor
        $is_kev = !empty($row['is_kev']);
        $epss   = (float)($row['epss_score'] ?? 0);
        $vendor = strtolower($row['matched_vendor'] ?? '');
        $matched_vendor = $vendor !== '' && in_array($vendor, $vendors, true);
        $cvss   = (float)($row['cvss_score'] ?? 0);

        $pass_kev  = $kev_always && $is_kev;
        $pass_epss = $epss >= ACTION_EPSS_THRESHOLD && $matched_vendor && $cvss >= $min_cvss;

        if (!$pass_kev && !$pass_epss) continue;

        $out[$id] = $row + [
            '_id'            => $id,
            '_kev_flag'      => $is_kev,
            '_epss_high'     => $epss >= ACTION_EPSS_THRESHOLD,
            '_vendor_match'  => $matched_vendor,
            '_pre_nvd'       => false,   // field not present in current schema
            '_customer_match'=> false,   // field not present in current schema
        ];
    }

    // Sort: KEV first, then EPSS desc, then CVSS desc
    uasort($out, function($a, $b) {
        if ($a['_kev_flag'] !== $b['_kev_flag']) return $b['_kev_flag'] <=> $a['_kev_flag'];
        $ea = (float)($a['epss_score'] ?? 0);
        $eb = (float)($b['epss_score'] ?? 0);
        if ($ea !== $eb) return $eb <=> $ea;
        return (float)($b['cvss_score'] ?? 0) <=> (float)($a['cvss_score'] ?? 0);
    });

    return array_slice($out, 0, ACTION_TOP_N, true);
}

function action_stats(array $cves): array {
    $kev = 0; $epss_hi = 0; $total = 0;
    foreach ($cves as $row) {
        if (!is_array($row)) continue;
        $total++;
        if (!empty($row['is_kev'])) $kev++;
        if ((float)($row['epss_score'] ?? 0) >= ACTION_EPSS_THRESHOLD) $epss_hi++;
    }
    return ['total' => $total, 'kev_count' => $kev, 'epss_high_count' => $epss_hi];
}

// ---- HTTP entry ----
require_role(['admin', 'operator', 'viewer']);
header('Content-Type: application/json');

$action = $_GET['action'] ?? $_POST['action'] ?? 'list';

if ($action === 'list') {
    $cves = action_load_cves();
    $wl   = action_load_watchlist();
    $dis  = action_load_dismissed();
    $items = action_filter($cves, $wl, $dis);
    echo json_encode([
        'ok'           => true,
        'count'        => count($items),
        'items'        => array_values($items),
        'generated_at' => gmdate('c'),
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'stats') {
    $cves = action_load_cves();
    echo json_encode(['ok' => true] + action_stats($cves), JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'dismiss') {
    require_role(['admin', 'operator']);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['ok' => false, 'error' => 'POST required']);
        exit;
    }
    $cve = trim($_POST['cve'] ?? '');
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'invalid CVE id']);
        exit;
    }
    $d = action_load_dismissed();
    $d[$cve] = ['at' => gmdate('c'), 'by' => $_SESSION['cwe_user'] ?? 'unknown'];
    action_save_dismissed($d);
    if (function_exists('audit_log_event')) {
        audit_log_event('cve_action_dismiss', ['object' => $cve]);
    }
    echo json_encode(['ok' => true, 'dismissed' => $cve]);
    exit;
}

http_response_code(400);
echo json_encode(['ok' => false, 'error' => 'unknown action']);

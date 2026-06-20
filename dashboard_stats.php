<?php
/**
 * Cyberwebeyeos — Dashboard Stats Endpoint (R38 T3.3)
 *
 * GET → JSON {
 *   trend_30d: [{date:'2026-05-01', count:N}, ...],
 *   type_distribution: {ip-src:N, domain:N, ...},
 *   tlp_distribution: {WHITE:N, GREEN:N, AMBER:N, RED:N},
 *   source_contribution: {manual:N, legacy:N, api:N, csv:N, ...},
 *   totals: {blacklist, whitelist, pending, expired, fp_reports}
 * }
 *
 * Tüm authed kullanıcılar erişebilir (read-only).
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/ioc_helpers.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: max-age=60');

$BLACKLIST = __DIR__ . '/blacklist.txt';
$WHITELIST = __DIR__ . '/whitelist.txt';
$PENDING = __DIR__ . '/pending_ips.json';
$FP_STATE = __DIR__ . '/fp_state.json';

$trend_30d = [];
$type_dist = [];
$tlp_dist  = ['WHITE'=>0,'GREEN'=>0,'AMBER'=>0,'RED'=>0];
$src_contrib = [];
$expired_count = 0;
$total_bl = 0;

// 30 gün boş bucket'la başla
$today = strtotime('today');
for ($i = 29; $i >= 0; $i--) {
    $trend_30d[date('Y-m-d', $today - $i * 86400)] = 0;
}

if (file_exists($BLACKLIST)) {
    foreach (file($BLACKLIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        $total_bl++;

        // Trend: entry tarihinden gün çıkar
        $ts = strtotime($e['date']);
        if ($ts !== false) {
            $day = date('Y-m-d', $ts);
            if (isset($trend_30d[$day])) $trend_30d[$day]++;
        }

        // Type distribution
        $type_dist[$e['type']] = ($type_dist[$e['type']] ?? 0) + 1;

        // TLP distribution
        if (isset($tlp_dist[$e['tlp']])) $tlp_dist[$e['tlp']]++;

        // Source contribution — added_by prefix
        $ab = $e['added_by'];
        $src_key = 'manual';
        if ($ab === 'legacy') $src_key = 'legacy';
        elseif (str_starts_with($ab, 'api:')) $src_key = 'api';
        elseif (str_starts_with($ab, 'csv:')) $src_key = 'csv';
        elseif (str_starts_with($ab, 'cidr-aggregate')) $src_key = 'aggregate';
        $src_contrib[$src_key] = ($src_contrib[$src_key] ?? 0) + 1;

        // Expired
        if (cwe_is_expired($e)) $expired_count++;
    }
}

// Whitelist count
$wl_count = 0;
if (file_exists($WHITELIST)) {
    foreach (file($WHITELIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        $wl_count++;
    }
}

// Pending
$pending = json_decode(@file_get_contents($PENDING), true);
$pending_count = count($pending['pending_ips'] ?? []);

// FP
$fp_state = json_decode(@file_get_contents($FP_STATE), true);
$fp_reports_total = 0;
foreach (($fp_state['fp_state'] ?? []) as $info) {
    $fp_reports_total += (int)($info['fp_count'] ?? 0);
}

// Format trend as array
$trend_arr = [];
foreach ($trend_30d as $date => $count) {
    $trend_arr[] = ['date' => $date, 'count' => $count];
}

echo json_encode([
    'ok' => true,
    'trend_30d' => $trend_arr,
    'type_distribution' => $type_dist,
    'tlp_distribution' => $tlp_dist,
    'source_contribution' => $src_contrib,
    'totals' => [
        'blacklist'    => $total_bl,
        'whitelist'    => $wl_count,
        'pending'      => $pending_count,
        'expired'      => $expired_count,
        'fp_reports'   => $fp_reports_total,
    ],
    'generated_at' => date('Y-m-d H:i:s'),
], JSON_UNESCAPED_UNICODE);

<?php
/**
 * Cyberwebeyeos — IoC Investigation History (R46 T5.1)
 *
 * GET ?value=<ioc>
 * Bir IoC'nin tüm yan-kanal verisini tek JSON'a topla:
 *   - audit_log.json: bu IoC'yi etkileyen tüm event'ler (regex match)
 *   - fp_state.json: FP raporları + reports[]
 *   - sighting_state.json: count + sources + first_seen + last_seen
 *   - enrichment_cache: GeoIP + VT (cache hit varsa)
 *   - Blacklist current state: matched entry + metadata
 *
 * Auth: tüm authed kullanıcılar (read-only).
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/ioc_helpers.php';
require_once __DIR__ . '/audit_log.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$value = trim($_GET['value'] ?? '');
if ($value === '') {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'value parametresi zorunlu']); exit;
}

$BASE = __DIR__;
$result = [
    'ok' => true,
    'value' => $value,
    'now' => date('Y-m-d H:i:s'),
];

// --- 1. Current blacklist entry (if exists) ---
$variants = [$value];
if (str_ends_with($value, '/32')) $variants[] = substr($value, 0, -3);
else $variants[] = $value . '/32';

$current = null;
if (file_exists($BASE . '/blacklist.txt')) {
    foreach (file($BASE . '/blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        if (in_array($e['value'], $variants, true)) {
            $current = $e;
            $current['is_expired'] = cwe_is_expired($e);
            break;
        }
    }
}
$result['current_entry'] = $current;

// --- 2. Audit events ---
$events = [];
if (file_exists($BASE . '/audit.log')) {
    $value_quoted = preg_quote($value, '/');
    $bare = preg_quote(rtrim($value, '/32'), '/');
    foreach (array_reverse(file($BASE . '/audit.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) as $line) {
        if (count($events) >= 200) break;
        // Strip line_hash prefix if present (T5.2 prep)
        $json_part = $line;
        if (strpos($line, '|') !== false && preg_match('/^[a-f0-9]{16,64}\|/', $line)) {
            $json_part = substr($line, strpos($line, '|') + 1);
        }
        // Quick text filter
        if (stripos($json_part, $value) === false && stripos($json_part, rtrim($value, '/32')) === false) continue;
        $e = json_decode($json_part, true);
        if (!is_array($e)) continue;
        $events[] = $e;
    }
}
$result['audit_events'] = $events;
$result['audit_count'] = count($events);

// --- 3. FP state ---
$fp = null;
$fp_data = @json_decode(@file_get_contents($BASE . '/fp_state.json'), true);
foreach ($variants as $v) {
    if (isset($fp_data['fp_state'][$v])) { $fp = $fp_data['fp_state'][$v]; break; }
}
$result['fp'] = $fp;

// --- 4. Sighting ---
$sighting = null;
$s_data = @json_decode(@file_get_contents($BASE . '/sighting_state.json'), true);
foreach ($variants as $v) {
    if (isset($s_data['sightings'][$v])) { $sighting = $s_data['sightings'][$v]; break; }
}
$result['sighting'] = $sighting;

// --- 5. Enrichment cache ---
$enrich_dir = $BASE . '/enrichment_cache';
$enrichments = [];
foreach ($variants as $v) {
    $base_v = strtolower($v);
    if (strpos($base_v, '/') !== false) $base_v = explode('/', $base_v)[0];
    $geo_file = $enrich_dir . '/' . md5($base_v) . '.json';
    if (file_exists($geo_file)) {
        $enrichments['geoip'] = @json_decode(@file_get_contents($geo_file), true);
        $enrichments['geoip']['cached_at'] = date('Y-m-d H:i:s', filemtime($geo_file));
    }
    $vt_file = $enrich_dir . '/vt_' . md5($base_v) . '.json';
    if (file_exists($vt_file)) {
        $enrichments['virustotal'] = @json_decode(@file_get_contents($vt_file), true);
        $enrichments['virustotal']['cached_at'] = date('Y-m-d H:i:s', filemtime($vt_file));
    }
}
$result['enrichments'] = $enrichments;

// --- 6. Pending state (whitelist↔blacklist conflict workflow) ---
$pending_match = null;
$p_data = @json_decode(@file_get_contents($BASE . '/pending_ips.json'), true);
foreach (($p_data['pending_ips'] ?? []) as $p) {
    if (in_array($p['ip'] ?? '', $variants, true)) { $pending_match = $p; break; }
}
$result['pending'] = $pending_match;

// --- 7. Whitelist match ---
$wl_match = null;
if (file_exists($BASE . '/whitelist.txt')) {
    foreach (file($BASE . '/whitelist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        $first = trim(explode('|', $line)[0]);
        if (in_array($first, $variants, true)) {
            $parts = explode('|', $line);
            $wl_match = [
                'value' => $first,
                'date' => $parts[1] ?? '',
                'user' => $parts[2] ?? '',
                'comment' => $parts[3] ?? '',
                'tlp' => $parts[4] ?? 'WHITE',
            ];
            break;
        }
    }
}
$result['whitelist'] = $wl_match;

// --- 8. Warninglist match (current) ---
$result['warninglist'] = cwe_warninglist_match($value);

// --- 9. Big Tech overlap (current) ---
$result['bigtech'] = cwe_bigtech_match($value);

echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

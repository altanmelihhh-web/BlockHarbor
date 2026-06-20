<?php
/**
 * Cyberwebeyeos — CVE Fetch (R43 T4.3)
 *
 * Sprint 4 #3 — KIRPILMIŞ MVP:
 *   - NVD CVE API 2.0 daily/incremental pull
 *   - CISA KEV catalog cross-check (boolean is_kev)
 *   - Vendor substring match (CPE complexity yok)
 *   - Tek state dosyası: cve_state.json
 *
 * YOK (Sprint 5+):
 *   - EPSS lookup (24h gecikme — yararsız)
 *   - ThreatFox CVE→IoC linkage (tag sistemi hayal)
 *   - L2/L3 product+version match (CPE tutarsız)
 *   - STIX 2.1 Vulnerability SDO TAXII export (0 consumer)
 *   - Full acknowledge workflow (dismiss + 30g auto-archive yeter)
 *
 * Modlar:
 *   CLI:  php cve_fetch.php [--bootstrap] [--days=N] [--quiet]
 *   Web:  POST /cve_fetch.php (admin)
 *
 * Cron: 0 6 * * * www-data /usr/bin/php cve_fetch.php --quiet
 */

require_once __DIR__ . '/ioc_helpers.php';

$IS_CLI = (php_sapi_name() === 'cli');
$STATE_FILE = __DIR__ . '/cve_state.json';
$WATCH_FILE = __DIR__ . '/vendor_watchlist.json';

$BOOTSTRAP = false; $DAYS = 7; $QUIET = false; $WEB_OWNER = '';
if ($IS_CLI) {
    foreach ($argv as $a) {
        if ($a === '--bootstrap') $BOOTSTRAP = true;
        elseif ($a === '--quiet' || $a === '-q') $QUIET = true;
        elseif (preg_match('/^--days=(\d+)$/', $a, $m)) $DAYS = max(1, min(30, (int)$m[1]));
    }
} else {
    require_once __DIR__ . '/blacklist_admin_auth.php';
    require_once __DIR__ . '/audit_log.php';
    require_role(['admin']);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        header('Content-Type: application/json');
        echo json_encode(['ok'=>false,'error'=>'POST required']); exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    $BOOTSTRAP = !empty($_POST['bootstrap']);
    if (!empty($_POST['days'])) $DAYS = max(1, min(30, (int)$_POST['days']));
    $WEB_OWNER = cwe_current_user() ?: 'web';
}

// Load watchlist
$wl = @json_decode(@file_get_contents($WATCH_FILE), true);
if (!is_array($wl) || empty($wl['vendors'])) {
    $err = ['ok'=>false, 'error'=>'vendor_watchlist.json eksik veya boş'];
    if ($IS_CLI) { fwrite(STDERR, $err['error']."\n"); exit(2); }
    echo json_encode($err); exit;
}
$vendors_lc = array_map('strtolower', $wl['vendors']);
$min_cvss = (float)($wl['min_cvss'] ?? 0);
$include_kev_always = !empty($wl['include_kev_always']);

// Load state
$state = @json_decode(@file_get_contents($STATE_FILE), true);
if (!is_array($state)) $state = ['cves'=>[], 'kev_index'=>[], 'last_sync'=>null, 'last_kev_sync'=>null];
if (!isset($state['cves'])) $state['cves'] = [];
if (!isset($state['kev_index'])) $state['kev_index'] = [];

function _fetch_url(string $url, array $headers = [], int $timeout = 30): ?string {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/1.0',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($code === 200 && $body) ? $body : null;
}

// ---- 1. CISA KEV sync ----
if (!$QUIET) echo "[" . date('Y-m-d H:i:s') . "] CISA KEV pulling...\n";
$kev_body = _fetch_url('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
$new_kev_count = 0;
if ($kev_body) {
    $kev_j = json_decode($kev_body, true);
    if (is_array($kev_j) && isset($kev_j['vulnerabilities'])) {
        $state['kev_index'] = [];
        foreach ($kev_j['vulnerabilities'] as $v) {
            $cid = $v['cveID'] ?? '';
            if ($cid) {
                $state['kev_index'][$cid] = [
                    'dateAdded' => $v['dateAdded'] ?? null,
                    'vendorProject' => $v['vendorProject'] ?? '',
                    'product' => $v['product'] ?? '',
                    'shortDescription' => $v['shortDescription'] ?? '',
                    'dueDate' => $v['dueDate'] ?? null,
                    'knownRansomwareCampaignUse' => $v['knownRansomwareCampaignUse'] ?? 'Unknown',
                ];
            }
        }
        $state['last_kev_sync'] = date('Y-m-d H:i:s');
        $new_kev_count = count($state['kev_index']);
        if (!$QUIET) echo "  KEV: {$new_kev_count} entries\n";
    }
}

// ---- 2. NVD CVE pull ----
if (!$QUIET) echo "[" . date('Y-m-d H:i:s') . "] NVD pulling...\n";

$now = time();
if ($BOOTSTRAP || empty($state['last_sync'])) {
    $start_iso = date('Y-m-d\TH:i:s.000', $now - $DAYS * 86400);
    $end_iso = date('Y-m-d\TH:i:s.000', $now);
    $param = 'pubStartDate';
} else {
    $start_iso = date('Y-m-d\TH:i:s.000', strtotime($state['last_sync']));
    $end_iso = date('Y-m-d\TH:i:s.000', $now);
    $param = 'lastModStartDate';
}
$param_end = $param === 'pubStartDate' ? 'pubEndDate' : 'lastModEndDate';

$matched_count = 0;
$startIdx = 0;
$page = 0;
do {
    $page++;
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?{$param}=" . urlencode($start_iso)
         . "&{$param_end}=" . urlencode($end_iso)
         . "&resultsPerPage=2000&startIndex={$startIdx}";
    if (!$QUIET) echo "  page {$page} startIdx={$startIdx} ... ";
    $body = _fetch_url($url, [], 45);
    if (!$body) { if (!$QUIET) echo "FAIL\n"; break; }
    $j = json_decode($body, true);
    if (!is_array($j) || !isset($j['vulnerabilities'])) { if (!$QUIET) echo "no vulns\n"; break; }
    $total = (int)($j['totalResults'] ?? 0);
    if (!$QUIET) echo "got " . count($j['vulnerabilities']) . " of {$total}\n";

    foreach ($j['vulnerabilities'] as $vw) {
        $c = $vw['cve'] ?? null;
        if (!$c) continue;
        $cid = $c['id'] ?? '';
        if (!$cid) continue;

        // Description + CPE strings concat — vendor substring search
        $desc_en = '';
        foreach (($c['descriptions'] ?? []) as $d) {
            if (($d['lang'] ?? '') === 'en') { $desc_en = $d['value'] ?? ''; break; }
        }
        $cpe_blob = '';
        foreach (($c['configurations'] ?? []) as $cfg) {
            foreach (($cfg['nodes'] ?? []) as $node) {
                foreach (($node['cpeMatch'] ?? []) as $cm) {
                    $cpe_blob .= ' ' . ($cm['criteria'] ?? '');
                }
            }
        }
        $search_blob = strtolower($desc_en . ' ' . $cpe_blob);

        $is_kev = isset($state['kev_index'][$cid]);
        $matched_vendor = null;
        foreach ($vendors_lc as $vend) {
            if (str_contains($search_blob, $vend)) { $matched_vendor = $vend; break; }
        }
        $relevant = $matched_vendor !== null || ($is_kev && $include_kev_always);
        if (!$relevant) continue;

        // CVSS
        $cvss_score = null; $cvss_severity = null; $cvss_vector = null;
        $metrics = $c['metrics'] ?? [];
        foreach (['cvssMetricV31','cvssMetricV30','cvssMetricV2'] as $mkey) {
            if (!empty($metrics[$mkey])) {
                $cd = $metrics[$mkey][0]['cvssData'] ?? null;
                if ($cd) {
                    $cvss_score = (float)($cd['baseScore'] ?? 0);
                    $cvss_severity = $cd['baseSeverity'] ?? ($metrics[$mkey][0]['baseSeverity'] ?? null);
                    $cvss_vector = $cd['vectorString'] ?? null;
                    break;
                }
            }
        }

        // Filter min_cvss (KEV bypass — always include KEV)
        if (!$is_kev && $cvss_score !== null && $cvss_score < $min_cvss) continue;

        // References
        $refs = [];
        foreach (($c['references'] ?? []) as $r) {
            if (isset($r['url'])) $refs[] = $r['url'];
        }

        // CWE
        $cwes = [];
        foreach (($c['weaknesses'] ?? []) as $w) {
            foreach (($w['description'] ?? []) as $wd) {
                if (preg_match('/^CWE-\d+$/', $wd['value'] ?? '')) $cwes[] = $wd['value'];
            }
        }

        // Preserve dismiss state if exists
        $existing = $state['cves'][$cid] ?? [];

        $state['cves'][$cid] = [
            'cve_id' => $cid,
            'published' => $c['published'] ?? null,
            'last_modified' => $c['lastModified'] ?? null,
            'description' => mb_substr($desc_en, 0, 1500),
            'cvss_score' => $cvss_score,
            'cvss_severity' => $cvss_severity,
            'cvss_vector' => $cvss_vector,
            'is_kev' => $is_kev,
            'kev_meta' => $is_kev ? $state['kev_index'][$cid] : null,
            'matched_vendor' => $matched_vendor,
            'cwes' => array_values(array_unique($cwes)),
            'references' => array_slice(array_unique($refs), 0, 10),
            'dismissed_at' => $existing['dismissed_at'] ?? null,
            'dismissed_by' => $existing['dismissed_by'] ?? null,
            'dismiss_note' => $existing['dismiss_note'] ?? null,
        ];
        $matched_count++;
    }

    $startIdx += count($j['vulnerabilities']);
    if ($startIdx >= $total) break;
    if ($page > 20) break; // safety
    sleep(7); // NVD rate (no key: 5 req/30s)
} while (true);

// R50 (T5.5): EPSS bulk lookup — 100 CVE/req batch (FIRST API)
if (!$QUIET) echo "[" . date('Y-m-d H:i:s') . "] EPSS pulling...\n";
$epss_updated = 0;
$cve_ids = array_keys($state['cves']);
foreach (array_chunk($cve_ids, 100) as $chunk) {
    $url = 'https://api.first.org/data/v1/epss?cve=' . urlencode(implode(',', $chunk));
    $body = _fetch_url($url, [], 20);
    if (!$body) continue;
    $j = json_decode($body, true);
    if (!is_array($j) || empty($j['data'])) continue;
    foreach ($j['data'] as $row) {
        $cid = $row['cve'] ?? '';
        if (!$cid || !isset($state['cves'][$cid])) continue;
        $state['cves'][$cid]['epss_score'] = isset($row['epss']) ? (float)$row['epss'] : null;
        $state['cves'][$cid]['epss_percentile'] = isset($row['percentile']) ? (float)$row['percentile'] : null;
        $state['cves'][$cid]['epss_date'] = $row['date'] ?? null;
        $epss_updated++;
    }
    usleep(500000); // 0.5s polite delay
}
if (!$QUIET) echo "  EPSS: {$epss_updated} CVE updated\n";

// Auto-dismiss: 30 günden eski + dismissed=false + KEV değil → otomatik dismiss
$auto_dismiss_days = (int)($wl['auto_dismiss_days'] ?? 30);
$auto_archived = 0;
foreach ($state['cves'] as $cid => &$cv) {
    if (!empty($cv['dismissed_at'])) continue;
    if (!empty($cv['is_kev'])) continue;
    $pub_ts = strtotime($cv['published'] ?? '0');
    if ($pub_ts && (time() - $pub_ts) > $auto_dismiss_days * 86400) {
        $cv['dismissed_at'] = date('Y-m-d H:i:s');
        $cv['dismissed_by'] = 'auto-archive';
        $cv['dismiss_note'] = "Auto-archived (>{$auto_dismiss_days} days, not KEV)";
        $auto_archived++;
    }
}
unset($cv);

$state['last_sync'] = date('Y-m-d H:i:s');

// Atomic write
$tmp = $STATE_FILE . '.tmp';
file_put_contents($tmp, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
rename($tmp, $STATE_FILE);
@chmod($STATE_FILE, 0664);

$payload = [
    'ok' => true,
    'cves_total' => count($state['cves']),
    'matched_this_run' => $matched_count,
    'kev_total' => $new_kev_count,
    'auto_archived' => $auto_archived,
    'last_sync' => $state['last_sync'],
    'window' => ['from'=>$start_iso, 'to'=>$end_iso, 'param'=>$param],
];

if (function_exists('audit_log_event')) {
    audit_log_event('cve_sync', [
        'matched' => $matched_count,
        'total' => count($state['cves']),
        'kev' => $new_kev_count,
        'auto_archived' => $auto_archived,
        'owner' => $WEB_OWNER ?: 'cron',
    ]);
}

if ($IS_CLI) { if (!$QUIET) print_r($payload); exit(0); }
echo json_encode($payload, JSON_UNESCAPED_UNICODE);

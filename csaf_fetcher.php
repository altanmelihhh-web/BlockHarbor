<?php
// SPRINT6-C1: CSAF 2.0 fetcher (5 publishers)

require_once __DIR__ . '/feed_health.php';

const CSAF_CONFIG = __DIR__ . '/vendor_psirt.json';
const CSAF_CACHE_DIR = __DIR__ . '/cve_cache/csaf';
const CSAF_CVE_STATE = __DIR__ . '/cve_state.json';
const CSAF_PER_PUB_TIMEOUT_S = 90;
const CSAF_PER_REQ_TIMEOUT_S = 15;
const CSAF_MAX_RETRIES = 3;
const CSAF_MAX_DOCS_PER_RUN_PER_PUB = 20;

function csaf_load_config(): array {
    if (!file_exists(CSAF_CONFIG)) return ['csaf_publishers' => []];
    $j = json_decode(file_get_contents(CSAF_CONFIG), true);
    return is_array($j) ? $j : ['csaf_publishers' => []];
}

function csaf_curl_get(string $url, ?string $if_modified = null, ?string $etag = null): array {
    $headers = ['Accept: application/json'];
    if ($if_modified) $headers[] = 'If-Modified-Since: ' . $if_modified;
    if ($etag) $headers[] = 'If-None-Match: ' . $etag;

    $attempt = 0;
    while ($attempt < CSAF_MAX_RETRIES) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => CSAF_PER_REQ_TIMEOUT_S,
            CURLOPT_USERAGENT => 'cyberwebeyeos-tip/sprint6',
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADER => true,
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        if ($resp === false) {
            $attempt++;
            sleep((int)pow(2, $attempt));
            continue;
        }
        $head = substr($resp, 0, $header_size);
        $body = substr($resp, $header_size);
        return ['code' => $code, 'body' => $body, 'headers' => $head];
    }
    return ['code' => 0, 'body' => '', 'headers' => '', 'error' => 'max_retries'];
}

function csaf_parse_provider_metadata(string $body): array {
    $j = json_decode($body, true);
    if (!is_array($j)) return [];
    $dists = [];
    foreach ($j['distributions'] ?? [] as $d) {
        if (!empty($d['directory_url'])) $dists[] = $d['directory_url'];
        if (!empty($d['rolie']['feeds'])) {
            foreach ($d['rolie']['feeds'] as $f) {
                if (!empty($f['url'])) $dists[] = $f['url'];
            }
        }
    }
    return ['publisher' => $j['publisher'] ?? null, 'distributions' => $dists];
}

function csaf_list_advisories(string $directory_url): array {
    $r = csaf_curl_get($directory_url);
    if ($r['code'] !== 200) return [];
    $j = json_decode($r['body'], true);
    $urls = [];
    if (is_array($j) && isset($j['feed']['entry']) && is_array($j['feed']['entry'])) {
        foreach ($j['feed']['entry'] as $entry) {
            foreach (($entry['link'] ?? []) as $link) {
                if (is_array($link) && ($link['rel'] ?? '') === 'self' && !empty($link['href'])) {
                    if (preg_match('/\.json$/', $link['href'])) $urls[] = $link['href'];
                }
            }
        }
    } else {
        if (preg_match_all('/href=["\']([^"\']+\.json)["\']/i', $r['body'], $m)) {
            foreach ($m[1] as $href) {
                if (preg_match('!^https?://!', $href)) $urls[] = $href;
                elseif (strpos($href, '/') === 0) {
                    $p = parse_url($directory_url);
                    $urls[] = $p['scheme'] . '://' . $p['host'] . $href;
                } else {
                    $urls[] = rtrim($directory_url, '/') . '/' . $href;
                }
            }
        }
    }
    return array_values(array_unique($urls));
}

function csaf_parse_advisory(string $body): ?array {
    $j = json_decode($body, true);
    if (!is_array($j)) return null;
    $cves = [];
    $vendor = '';
    foreach (($j['vulnerabilities'] ?? []) as $v) {
        if (!empty($v['cve'])) $cves[] = $v['cve'];
    }
    if (!empty($j['document']['publisher']['name'])) $vendor = strtolower($j['document']['publisher']['name']);
    $tracking_id = $j['document']['tracking']['id'] ?? '';
    $published = $j['document']['tracking']['initial_release_date'] ?? gmdate('c');
    $cvss = 0.0;
    foreach (($j['vulnerabilities'] ?? []) as $v) {
        foreach (($v['scores'] ?? []) as $s) {
            $score = (float)($s['cvss_v3']['baseScore'] ?? $s['cvss_v4']['baseScore'] ?? 0);
            if ($score > $cvss) $cvss = $score;
        }
    }
    return [
        'tracking_id' => $tracking_id,
        'cves' => array_values(array_unique($cves)),
        'vendor' => $vendor,
        'published' => $published,
        'cvss' => $cvss,
    ];
}

function csaf_merge_into_cve_state(array $advisory, string $publisher_name): int {
    if (empty($advisory['cves'])) return 0;
    $state_file = CSAF_CVE_STATE;

    $fp = fopen($state_file, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return 0; // cannot acquire lock — skip safely
    }

    // Read INSIDE lock (prevents concurrent read-modify-write race)
    $raw = stream_get_contents($fp);
    // Match T3 schema: { "cves": {...}, ... }
    $state = $raw ? (json_decode($raw, true) ?: []) : [];
    if (!isset($state['cves']) || !is_array($state['cves'])) $state['cves'] = [];

    $added = 0;
    foreach ($advisory['cves'] as $cve) {
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) continue;
        $existed = isset($state['cves'][$cve]);
        $row = $state['cves'][$cve] ?? [];
        $row['cve_id'] = $cve;
        $row['matched_vendor'] = $row['matched_vendor'] ?? $advisory['vendor'] ?? '';
        $row['cvss_score'] = max($row['cvss_score'] ?? 0, $advisory['cvss']);
        $row['published'] = $row['published'] ?? $advisory['published'];
        $row['sources'] = $row['sources'] ?? [];
        if (!in_array('csaf:' . $publisher_name, $row['sources'], true)) {
            $row['sources'][] = 'csaf:' . $publisher_name;
        }
        if (!$existed) {
            $row['pre_nvd'] = true;
            $row['first_seen_by'] = 'csaf:' . $publisher_name;
            $row['first_seen_at'] = gmdate('c');
            $added++;
        }
        $state['cves'][$cve] = $row;
    }

    // Write INSIDE same lock
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return $added;
}

function csaf_fetcher_run_one(array $pub, bool $dry_run = false): array {
    $name = $pub['name'] ?? '?';
    $pub_dir = CSAF_CACHE_DIR . '/' . preg_replace('/[^a-z0-9_-]/i', '_', $name);
    if (!is_dir($pub_dir)) @mkdir($pub_dir, 0775, true);

    if ($dry_run) {
        feed_health_heartbeat('csaf:' . $name, [
            'url' => $pub['provider_metadata'] ?? '',
            'http_status' => 200, 'bytes_received' => 0, 'parser_ok' => true,
            'entries_extracted' => 0,
            'raw_body' => '{"dry":true}',
            'format' => 'json',
        ]);
        return ['publisher' => $name, 'ok' => true, 'source' => 'dry-run', 'advisories' => 0, 'new_cves' => 0];
    }

    $start = time();
    $meta_resp = csaf_curl_get($pub['provider_metadata']);
    if ($meta_resp['code'] !== 200) {
        feed_health_heartbeat('csaf:' . $name, [
            'url' => $pub['provider_metadata'], 'http_status' => $meta_resp['code'],
            'bytes_received' => strlen($meta_resp['body']), 'parser_ok' => false,
            'entries_extracted' => 0, 'raw_body' => $meta_resp['body'], 'format' => 'json',
        ]);
        return ['publisher' => $name, 'ok' => false, 'http' => $meta_resp['code']];
    }
    $proceed = feed_health_heartbeat('csaf:' . $name, [
        'url' => $pub['provider_metadata'], 'http_status' => 200,
        'bytes_received' => strlen($meta_resp['body']), 'parser_ok' => true,
        'entries_extracted' => 0, 'raw_body' => $meta_resp['body'], 'format' => 'json',
    ]);
    if (!$proceed) {
        return ['publisher' => $name, 'ok' => false, 'reason' => 'schema_drift_or_disabled'];
    }

    $meta = csaf_parse_provider_metadata($meta_resp['body']);
    $advisory_count = 0;
    $new_cves = 0;
    foreach ($meta['distributions'] as $dir) {
        if ((time() - $start) > CSAF_PER_PUB_TIMEOUT_S) break;
        $urls = csaf_list_advisories($dir);
        foreach (array_slice($urls, 0, CSAF_MAX_DOCS_PER_RUN_PER_PUB) as $adv_url) {
            if ((time() - $start) > CSAF_PER_PUB_TIMEOUT_S) break;
            $cache_file = $pub_dir . '/' . md5($adv_url) . '.json';
            if (file_exists($cache_file)) continue;
            $adv_resp = csaf_curl_get($adv_url);
            if ($adv_resp['code'] !== 200) continue;
            $parsed = csaf_parse_advisory($adv_resp['body']);
            if (!$parsed) continue;
            file_put_contents($cache_file, $adv_resp['body']);
            $new_cves += csaf_merge_into_cve_state($parsed, $name);
            $advisory_count++;
        }
    }
    return ['publisher' => $name, 'ok' => true, 'advisories' => $advisory_count, 'new_cves' => $new_cves];
}

function csaf_fetcher_run_all(bool $dry_run = false): array {
    $cfg = csaf_load_config();
    if (!is_dir(CSAF_CACHE_DIR)) @mkdir(CSAF_CACHE_DIR, 0775, true);
    $results = [];
    foreach (($cfg['csaf_publishers'] ?? []) as $pub) {
        if (empty($pub['enabled'])) continue;
        $results[] = csaf_fetcher_run_one($pub, $dry_run);
    }
    $total_new = array_sum(array_column($results, 'new_cves'));
    return ['ok' => true, 'publishers' => $results, 'new_cves_total' => $total_new, 'generated_at' => gmdate('c')];
}

function csaf_fetcher_dry_run(): array {
    return csaf_fetcher_run_all(true);
}

if (php_sapi_name() === 'cli') {
    $dry = in_array('--dry-run', $argv ?? [], true);
    echo json_encode(csaf_fetcher_run_all($dry), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}

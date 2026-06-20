<?php
// SPRINT6-C2: Fortinet + Palo Alto PSIRT RSS → CVE-ID discovery (no body parse)

require_once __DIR__ . '/feed_health.php';

const PSIRT_CONFIG = __DIR__ . '/vendor_psirt.json';
const PSIRT_CACHE_DIR = __DIR__ . '/cve_cache/psirt';
const PSIRT_CVE_STATE = __DIR__ . '/cve_state.json';

function psirt_load_config(): array {
    if (!file_exists(PSIRT_CONFIG)) return ['rss_publishers' => []];
    $j = json_decode(file_get_contents(PSIRT_CONFIG), true);
    return is_array($j) ? $j : ['rss_publishers' => []];
}

function psirt_rss_extract_cves(string $rss_body): array {
    $cves = [];
    if (preg_match_all('/\bCVE-\d{4}-\d{4,}\b/i', $rss_body, $m)) {
        foreach ($m[0] as $c) $cves[] = strtoupper($c);
    }
    return array_values(array_unique($cves));
}

function psirt_rss_extract_items(string $rss_body): array {
    $items = [];
    $xml = @simplexml_load_string($rss_body);
    if ($xml === false) return $items;
    $channel = $xml->channel ?? $xml;
    foreach (($channel->item ?? []) as $item) {
        $title = (string)$item->title;
        $desc = (string)$item->description;
        $link = (string)$item->link;
        $pub = (string)$item->pubDate;
        $combined = "$title $desc";
        $cves = psirt_rss_extract_cves($combined);
        foreach ($cves as $cve) {
            $items[] = ['cve' => $cve, 'title' => $title, 'link' => $link, 'published' => $pub];
        }
    }
    return $items;
}

function psirt_merge_cve(string $cve, string $vendor, string $title, string $link, string $published): bool {
    $fp = fopen(PSIRT_CVE_STATE, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return false; // cannot acquire lock — skip safely
    }

    // Read INSIDE lock (prevents concurrent read-modify-write race)
    $raw = stream_get_contents($fp);
    $state = $raw ? (json_decode($raw, true) ?: []) : [];
    if (!isset($state['cves']) || !is_array($state['cves'])) $state['cves'] = [];

    $existed = isset($state['cves'][$cve]);
    $row = $state['cves'][$cve] ?? [];
    $row['cve_id'] = $cve;
    $row['matched_vendor'] = $row['matched_vendor'] ?? $vendor;
    $row['sources'] = $row['sources'] ?? [];
    if (!in_array('psirt-rss:' . $vendor, $row['sources'], true)) {
        $row['sources'][] = 'psirt-rss:' . $vendor;
    }
    $row['psirt_title'] = $row['psirt_title'] ?? $title;
    $row['psirt_link'] = $row['psirt_link'] ?? $link;
    $row['published'] = $row['published'] ?? $published;
    if (!$existed) {
        $row['pre_nvd'] = true;
        $row['first_seen_by'] = 'psirt-rss:' . $vendor;
        $row['first_seen_at'] = gmdate('c');
    }
    $state['cves'][$cve] = $row;

    // Write INSIDE same lock
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return !$existed;
}

function psirt_rss_run_one(array $pub, bool $dry_run = false): array {
    $name = $pub['name'] ?? '?';
    $url = $pub['rss_url'] ?? '';
    if (!is_dir(PSIRT_CACHE_DIR)) @mkdir(PSIRT_CACHE_DIR, 0775, true);
    if ($dry_run) {
        feed_health_heartbeat('psirt-rss:' . $name, [
            'url' => $url, 'http_status' => 200, 'bytes_received' => 0, 'parser_ok' => true,
            'entries_extracted' => 0, 'raw_body' => '<rss></rss>', 'format' => 'rss',
        ]);
        return ['publisher' => $name, 'ok' => true, 'source' => 'dry-run', 'items' => 0, 'new_cves' => 0];
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/sprint6',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code !== 200 || !$body) {
        feed_health_heartbeat('psirt-rss:' . $name, [
            'url' => $url, 'http_status' => $code, 'bytes_received' => strlen($body ?? ''),
            'parser_ok' => false, 'entries_extracted' => 0,
            'raw_body' => $body ?? '', 'format' => 'rss',
        ]);
        return ['publisher' => $name, 'ok' => false, 'http' => $code];
    }

    $items = psirt_rss_extract_items($body);
    $proceed = feed_health_heartbeat('psirt-rss:' . $name, [
        'url' => $url, 'http_status' => 200, 'bytes_received' => strlen($body),
        'parser_ok' => true, 'entries_extracted' => count($items),
        'raw_body' => $body, 'format' => 'rss',
    ]);
    if (!$proceed) {
        return ['publisher' => $name, 'ok' => false, 'reason' => 'schema_drift_or_disabled'];
    }

    $new = 0;
    foreach ($items as $it) {
        if (psirt_merge_cve($it['cve'], $name, $it['title'], $it['link'], $it['published'])) $new++;
    }
    return ['publisher' => $name, 'ok' => true, 'items' => count($items), 'new_cves' => $new];
}

function psirt_rss_run_all(bool $dry_run = false): array {
    $cfg = psirt_load_config();
    $results = [];
    foreach (($cfg['rss_publishers'] ?? []) as $pub) {
        if (empty($pub['enabled'])) continue;
        $results[] = psirt_rss_run_one($pub, $dry_run);
    }
    return ['ok' => true, 'publishers' => $results, 'generated_at' => gmdate('c')];
}

if (php_sapi_name() === 'cli') {
    $dry = in_array('--dry-run', $argv ?? [], true);
    echo json_encode(psirt_rss_run_all($dry), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}

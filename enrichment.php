<?php
/**
 * Cyberwebeyeos — On-Demand Enrichment Endpoint (R31 T2.1)
 *
 * GET ?value=<IP|domain>
 *
 * Provider:
 *   1. ip-api.com (default, no key, 45 req/min, free)
 *   2. Lokal MaxMind mmdb (/var/www/html/geoip/GeoLite2-{City,ASN}.mmdb)
 *      — composer require geoip2/geoip2 gerektirir
 *
 * Cache: enrichment_cache/{md5(value)}.json, TTL 24h
 *
 * Response:
 *   {
 *     ok: true,
 *     value: "8.8.8.8",
 *     country: "United States", country_code: "US", flag: "🇺🇸",
 *     city: "Mountain View", region: "California",
 *     asn: 15169, org: "Google LLC", isp: "Google LLC",
 *     lat: 37.4, lon: -122.0,
 *     source: "ip-api.com" | "maxmind-mmdb" | "cache",
 *     cached_at: "2026-05-21 11:45:00",
 *     ttl_remaining_sec: 86400
 *   }
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: max-age=3600');

$value = trim($_GET['value'] ?? '');
$action = trim($_GET['action'] ?? 'geo');
if ($value === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'value parametresi zorunlu']);
    exit;
}

// R39 (T3.4): VirusTotal v3 lookup
if ($action === 'vt') {
    $cfg = @include __DIR__ . '/auth_config.php';
    $vt_key = trim($cfg['vt_api_key'] ?? '');
    if ($vt_key === '') {
        http_response_code(503);
        echo json_encode(['ok'=>false, 'error'=>'VT API key yok. auth_config.php → vt_api_key'])
        ; exit;
    }
    require_once __DIR__ . '/ioc_helpers.php';
    $vt_cache_dir = __DIR__ . '/enrichment_cache';
    if (!is_dir($vt_cache_dir)) @mkdir($vt_cache_dir, 0775, true);
    $vt_cache = $vt_cache_dir . '/vt_' . md5(strtolower($value)) . '.json';
    $TTL_VT = 86400;
    if (file_exists($vt_cache) && (time() - filemtime($vt_cache)) < $TTL_VT) {
        $cached = json_decode(@file_get_contents($vt_cache), true);
        if (is_array($cached)) {
            $cached['source'] = 'cache';
            $cached['cached_at'] = date('Y-m-d H:i:s', filemtime($vt_cache));
            echo json_encode($cached, JSON_UNESCAPED_UNICODE); exit;
        }
    }
    // Tip → VT endpoint mapping
    $type = cwe_detect_type($value);
    $vt_endpoint = null;
    if (in_array($type, ['ip-src','ip-dst'], true)) {
        $base = $value; if (strpos($base, '/') !== false) $base = explode('/', $base)[0];
        $vt_endpoint = 'https://www.virustotal.com/api/v3/ip_addresses/' . urlencode($base);
    } elseif (in_array($type, ['domain','hostname'], true)) {
        $vt_endpoint = 'https://www.virustotal.com/api/v3/domains/' . urlencode($value);
    } elseif (in_array($type, ['file-md5','file-sha1','file-sha256'], true)) {
        $vt_endpoint = 'https://www.virustotal.com/api/v3/files/' . urlencode($value);
    } elseif ($type === 'url') {
        $url_id = rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $vt_endpoint = 'https://www.virustotal.com/api/v3/urls/' . $url_id;
    } else {
        echo json_encode(['ok'=>false, 'error'=>"VT desteklenmeyen tip: $type"]); exit;
    }

    $ch = curl_init($vt_endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['x-apikey: ' . $vt_key, 'accept: application/json'],
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/1.0',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code === 401) { echo json_encode(['ok'=>false, 'error'=>'VT API key invalid', 'http'=>401]); exit; }
    if ($code === 429) { echo json_encode(['ok'=>false, 'error'=>'VT rate limit (4 req/min)', 'http'=>429]); exit; }
    if ($code === 404) { echo json_encode(['ok'=>true, 'value'=>$value, 'found'=>false, 'message'=>'VT: bilinmiyor']); exit; }
    if ($code !== 200 || !$body) { echo json_encode(['ok'=>false, 'error'=>'VT HTTP '.$code]); exit; }

    $j = json_decode($body, true);
    $stats = $j['data']['attributes']['last_analysis_stats'] ?? null;
    if (!$stats) { echo json_encode(['ok'=>true, 'value'=>$value, 'found'=>false, 'raw_truncated'=>substr($body, 0, 300)]); exit; }

    $malicious = (int)($stats['malicious'] ?? 0);
    $suspicious = (int)($stats['suspicious'] ?? 0);
    $harmless = (int)($stats['harmless'] ?? 0);
    $undetected = (int)($stats['undetected'] ?? 0);
    $total = $malicious + $suspicious + $harmless + $undetected;
    $score = $total > 0 ? round((($malicious + $suspicious) / $total) * 100, 1) : 0;

    $result = [
        'ok' => true,
        'value' => $value,
        'found' => true,
        'type' => $type,
        'vt_score' => $score,             // 0-100, yüksek = daha kötü
        'malicious' => $malicious,
        'suspicious' => $suspicious,
        'harmless' => $harmless,
        'undetected' => $undetected,
        'total_engines' => $total,
        'reputation' => (int)($j['data']['attributes']['reputation'] ?? 0),
        'last_analysis_date' => isset($j['data']['attributes']['last_analysis_date'])
            ? date('Y-m-d H:i:s', (int)$j['data']['attributes']['last_analysis_date']) : null,
        'source' => 'virustotal',
        'cached_at' => date('Y-m-d H:i:s'),
        'ttl_remaining_sec' => $TTL_VT,
    ];
    @file_put_contents($vt_cache, json_encode($result, JSON_UNESCAPED_UNICODE));
    @chmod($vt_cache, 0664);
    echo json_encode($result, JSON_UNESCAPED_UNICODE);
    exit;
}

// Bizim helper'ı reuse — IP/CIDR ise base IP'yi al
require_once __DIR__ . '/ioc_helpers.php';
$type = cwe_detect_type($value);
if (!in_array($type, ['ip-src','ip-dst','cidr','ipv6','domain','hostname'], true)) {
    echo json_encode(['ok' => false, 'error' => 'Enrichment yalnız IP/CIDR/domain için: type=' . $type]);
    exit;
}

// CIDR/path-suffix temizleme — sadece IP/domain base'i al
$lookup = $value;
if (strpos($lookup, '/') !== false) $lookup = explode('/', $lookup)[0];

$CACHE_DIR = __DIR__ . '/enrichment_cache';
if (!is_dir($CACHE_DIR)) @mkdir($CACHE_DIR, 0775, true);
$cache_file = $CACHE_DIR . '/' . md5(strtolower($lookup)) . '.json';
$TTL = 86400; // 24h

// Cache hit?
if (file_exists($cache_file)) {
    $age = time() - filemtime($cache_file);
    if ($age < $TTL) {
        $data = json_decode(@file_get_contents($cache_file), true);
        if (is_array($data)) {
            $data['source'] = 'cache';
            $data['cached_at'] = date('Y-m-d H:i:s', filemtime($cache_file));
            $data['ttl_remaining_sec'] = $TTL - $age;
            echo json_encode($data, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }
}

/**
 * Country code → Unicode flag emoji (regional indicator)
 */
function _enr_country_flag(string $code): string {
    $code = strtoupper(trim($code));
    if (strlen($code) !== 2 || !ctype_alpha($code)) return '';
    return mb_chr(0x1F1E6 + ord($code[0]) - 65, 'UTF-8') . mb_chr(0x1F1E6 + ord($code[1]) - 65, 'UTF-8');
}

/**
 * Provider 1: ip-api.com (default).
 */
function _enr_via_ip_api(string $lookup): ?array {
    $fields = 'status,message,country,countryCode,region,regionName,city,as,asname,isp,org,lat,lon,query';
    $url = 'http://ip-api.com/json/' . urlencode($lookup) . '?fields=' . urlencode($fields);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/1.0',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200 || !$body) return null;
    $j = json_decode($body, true);
    if (!is_array($j) || ($j['status'] ?? '') !== 'success') return null;
    $asn = 0; $asorg = '';
    if (!empty($j['as'])) {
        if (preg_match('/^AS(\d+)\s+(.+)$/i', $j['as'], $m)) {
            $asn = (int)$m[1]; $asorg = $m[2];
        } else { $asorg = $j['as']; }
    }
    return [
        'value'        => $lookup,
        'country'      => $j['country'] ?? '',
        'country_code' => $j['countryCode'] ?? '',
        'flag'         => _enr_country_flag($j['countryCode'] ?? ''),
        'city'         => $j['city'] ?? '',
        'region'       => $j['regionName'] ?? '',
        'asn'          => $asn,
        'org'          => $asorg ?: ($j['org'] ?? ''),
        'isp'          => $j['isp'] ?? '',
        'lat'          => $j['lat'] ?? null,
        'lon'          => $j['lon'] ?? null,
        'provider'     => 'ip-api.com',
    ];
}

/**
 * Provider 2: MaxMind mmdb (geoip2/geoip2 composer package required).
 */
function _enr_via_mmdb(string $lookup): ?array {
    $geoip_dir = '/var/www/html/geoip';
    $city_db = $geoip_dir . '/GeoLite2-City.mmdb';
    $asn_db  = $geoip_dir . '/GeoLite2-ASN.mmdb';
    if (!file_exists($city_db) || !class_exists('\\GeoIp2\\Database\\Reader')) return null;
    try {
        $cityReader = new \GeoIp2\Database\Reader($city_db);
        $cityRec = $cityReader->city($lookup);
        $asn = 0; $org = '';
        if (file_exists($asn_db)) {
            $asnReader = new \GeoIp2\Database\Reader($asn_db);
            $asnRec = $asnReader->asn($lookup);
            $asn = (int)$asnRec->autonomousSystemNumber;
            $org = (string)$asnRec->autonomousSystemOrganization;
        }
        $cc = $cityRec->country->isoCode ?? '';
        return [
            'value'        => $lookup,
            'country'      => $cityRec->country->name ?? '',
            'country_code' => $cc,
            'flag'         => _enr_country_flag($cc),
            'city'         => $cityRec->city->name ?? '',
            'region'       => $cityRec->mostSpecificSubdivision->name ?? '',
            'asn'          => $asn,
            'org'          => $org,
            'isp'          => $org,
            'lat'          => $cityRec->location->latitude ?? null,
            'lon'          => $cityRec->location->longitude ?? null,
            'provider'     => 'maxmind-mmdb',
        ];
    } catch (\Throwable $ex) {
        return null;
    }
}

// Lookup chain: mmdb → ip-api fallback
$data = _enr_via_mmdb($lookup);
if (!$data) $data = _enr_via_ip_api($lookup);

if (!$data) {
    echo json_encode([
        'ok' => false,
        'value' => $lookup,
        'error' => 'Enrichment provider tüm denemelerinde başarısız (network veya kota?)',
    ]);
    exit;
}

$data['ok'] = true;
$data['source'] = $data['provider'];
$data['cached_at'] = date('Y-m-d H:i:s');
$data['ttl_remaining_sec'] = $TTL;
@file_put_contents($cache_file, json_encode($data, JSON_UNESCAPED_UNICODE));
@chmod($cache_file, 0664);

echo json_encode($data, JSON_UNESCAPED_UNICODE);

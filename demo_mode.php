<?php
/**
 * BlockHarbor — Demo Mode
 *
 * Loaded through php.ini `auto_prepend_file` when DEMO_MODE=true, so it runs
 * before every request without any per-endpoint wiring. Outside demo mode the
 * file is never loaded and the application behaves exactly as before.
 *
 * Responsibilities:
 *   1. Deny-by-default write lock  — everything except GET/HEAD is rejected,
 *      plus a denylist for scripts that mutate state on GET.
 *   2. Demo banner                 — injected into HTML responses only.
 *   3. Stub enrichment responses   — no outbound calls to VT/GreyNoise/Shodan.
 *
 * The write lock is deliberately a front-door check rather than a per-file
 * guard: several endpoints (threatfox.php, migrate_blacklist_schema.php) ship
 * without any auth of their own, so an allowlist at the entry point is the only
 * safe way to expose this application publicly.
 */

if (!function_exists('demo_is_on')) {

    function demo_is_on(): bool
    {
        $v = getenv('DEMO_MODE');
        return $v !== false && strtolower(trim((string)$v)) === 'true';
    }

    /** Scripts that mutate state even on GET, or that must never run in a demo. */
    function demo_denied_scripts(): array
    {
        return [
            'migrate_blacklist_schema.php',
            'migrate_lists_sprint7.php',
            'threatfox.php',
            'csaf_fetcher.php',
            'psirt_rss_fetcher.php',
            'cve_fetch.php',
            'warninglist_sync.php',
            'bigtech_whitelist_sync.php',
            'cidr_aggregate.php',
            'sighting.php',
            'users.php',
            'notify.php',
        ];
    }

    /** POST is allowed only for the login/logout flow. */
    function demo_write_allowed_scripts(): array
    {
        return ['login.php', 'logout.php'];
    }

    function demo_current_script(): string
    {
        return basename((string)($_SERVER['SCRIPT_NAME'] ?? ''));
    }

    function demo_wants_json(): bool
    {
        $accept = (string)($_SERVER['HTTP_ACCEPT'] ?? '');
        if (stripos($accept, 'application/json') !== false) {
            return true;
        }
        $xhr = (string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '');
        return strtolower($xhr) === 'xmlhttprequest';
    }

    function demo_block(string $reason): void
    {
        http_response_code(403);
        if (demo_wants_json()) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok'    => false,
                'error' => 'demo_mode',
                'detail' => $reason,
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><meta charset="utf-8">'
           . '<title>Demo mode — read only</title>'
           . '<div style="max-width:34rem;margin:4rem auto;font:15px/1.6 system-ui,sans-serif;'
           . 'padding:1.5rem;border:1px solid #f59e0b;border-radius:8px;background:#fffbeb;color:#78350f">'
           . '<strong style="display:block;font-size:1.05rem;margin-bottom:.5rem">'
           . 'This action is disabled in the public demo</strong>'
           . '<p style="margin:.4rem 0">' . htmlspecialchars($reason, ENT_QUOTES, 'UTF-8') . '</p>'
           . '<p style="margin:.4rem 0">The demo is read-only so that the dataset stays intact '
           . 'for the next visitor. Run it locally to exercise the write paths.</p>'
           . '<p style="margin:1rem 0 0"><a href="cyberwebeyeosblacklistadmin.php" '
           . 'style="color:#92400e">&larr; Back to the dashboard</a></p></div>';
        exit;
    }

    /** Insert the demo banner directly after the opening <body> tag. */
    function demo_inject_banner(string $html): string
    {
        if (stripos($html, '<body') === false || stripos($html, 'bh-demo-banner') !== false) {
            return $html;
        }
        foreach (headers_list() as $h) {
            if (stripos($h, 'content-type:') === 0 && stripos($h, 'text/html') === false) {
                return $html;
            }
        }

        $banner = '<div id="bh-demo-banner" style="position:sticky;top:0;z-index:99999;'
            . 'background:#b45309;color:#fff;padding:9px 14px;font:600 13px/1.45 system-ui,'
            . '-apple-system,Segoe UI,sans-serif;letter-spacing:.2px;text-align:center;'
            . 'box-shadow:0 1px 4px rgba(0,0,0,.25)">'
            . 'DEMO &mdash; veriler &ouml;rnektir, ger&ccedil;ek veri girmeyiniz. '
            . '<span style="font-weight:400;opacity:.92">Read-only demo with synthetic data '
            . '(RFC 5737 addresses). Do not enter real indicators.</span>'
            . '</div>';

        return preg_replace('/(<body\b[^>]*>)/i', '$1' . $banner, $html, 1) ?? $html;
    }

    // ---------------------------------------------------------------- stubs --

    /** Shape matches enrichment.php's action=vt response contract. */
    function demo_fake_virustotal(string $value, string $type): array
    {
        $n = crc32($value);
        $malicious  = $n % 17;
        $suspicious = $n % 5;
        $harmless   = 60 + ($n % 12);
        $undetected = 8 + ($n % 7);
        $total = $malicious + $suspicious + $harmless + $undetected;
        return [
            'ok'                 => true,
            'value'              => $value,
            'found'              => true,
            'type'               => $type,
            'vt_score'           => $total > 0 ? round((($malicious + $suspicious) / $total) * 100, 1) : 0,
            'malicious'          => $malicious,
            'suspicious'         => $suspicious,
            'harmless'           => $harmless,
            'undetected'         => $undetected,
            'total_engines'      => $total,
            'reputation'         => -1 * ($n % 40),
            'last_analysis_date' => date('Y-m-d H:i:s', time() - ($n % 86400)),
            'source'             => 'demo-stub',
            'cached_at'          => date('Y-m-d H:i:s'),
            'ttl_remaining_sec'  => 86400,
            'demo'               => true,
        ];
    }

    /** Shape matches _enr_via_ip_api() in enrichment.php, including 'provider'. */
    function demo_fake_geo(string $lookup): array
    {
        $n = crc32($lookup);
        $rows = [
            ['TR', 'Turkey',        'Istanbul',  'Marmara',    9121,  'Turk Telekom',  'TTNet',        41.01, 28.98],
            ['NL', 'Netherlands',   'Amsterdam', 'N. Holland', 60781, 'LeaseWeb',      'LeaseWeb NL',  52.37, 4.90],
            ['US', 'United States', 'Ashburn',   'Virginia',   14618, 'Amazon AES',    'Amazon.com',   39.04, -77.49],
            ['DE', 'Germany',       'Frankfurt', 'Hesse',      24940, 'Hetzner Online','Hetzner',      50.11, 8.68],
            ['RU', 'Russia',        'Moscow',    'Moscow',     49505, 'Selectel',      'Selectel Ltd', 55.75, 37.62],
        ];
        $r = $rows[$n % count($rows)];
        return [
            'value'        => $lookup,
            'country'      => $r[1],
            'country_code' => $r[0],
            'flag'         => function_exists('_enr_country_flag') ? _enr_country_flag($r[0]) : '',
            'city'         => $r[2],
            'region'       => $r[3],
            'asn'          => $r[4],
            'org'          => $r[5],
            'isp'          => $r[6],
            'lat'          => $r[7],
            'lon'          => $r[8],
            'provider'     => 'demo-stub',
            'demo'         => true,
        ];
    }

    /** Shape matches greynoise_cve_search(). */
    function demo_fake_greynoise(string $cve): array
    {
        $n = crc32($cve);
        $count = $n % 6;
        $ips = [];
        for ($i = 0; $i < $count; $i++) {
            $ips[] = '198.51.100.' . (10 + (($n + $i * 37) % 240));
        }
        return [
            'ips'    => $ips,
            'count'  => $count,
            'cve'    => $cve,
            'source' => 'demo-stub',
            'demo'   => true,
        ];
    }

    /** Shape matches shodan_exposure_check_ip(). */
    function demo_fake_shodan(string $ip): array
    {
        $n = crc32($ip);
        $portsets = [[22, 80, 443], [80, 8080], [443], [21, 22, 3389], [25, 110, 143]];
        $vulnsets = [[], ['CVE-2026-10041'], ['CVE-2026-10077', 'CVE-2026-10112'], []];
        return [
            'ok'        => true,
            'ip'        => $ip,
            'ports'     => $portsets[$n % count($portsets)],
            'vulns'     => $vulnsets[$n % count($vulnsets)],
            'cpes'      => [],
            'hostnames' => [],
            'tags'      => ($n % 3 === 0) ? ['self-signed'] : [],
            'source'    => 'demo-stub',
            'demo'      => true,
        ];
    }

    // ------------------------------------------------------------ enforcement --

    if (demo_is_on() && PHP_SAPI !== 'cli') {
        // SCRIPT_NAME is the authoritative resolved script under Apache/mod_php
        // and is what the allowlist is keyed on. The raw request path is only
        // ever used to *add* denials, never to grant one, so a crafted
        // PATH_INFO such as /delete.php/login.php cannot unlock a write.
        $script  = demo_current_script();
        $method  = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $uripath = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);

        // Guard against path confusion such as POST /delete.php/login.php,
        // where SCRIPT_NAME resolves to delete.php but the URI ends in a name
        // that appears on the write allowlist. If both the executed script and
        // the last URI segment look like PHP files, they must be the same file.
        $uriLeaf = basename($uripath);
        if (substr($script, -4) === '.php' && substr($uriLeaf, -4) === '.php'
            && strcasecmp($script, $uriLeaf) !== 0) {
            demo_block('Request path does not match the resolved script.');
        }

        foreach (demo_denied_scripts() as $denied) {
            if ($script === $denied || stripos($uripath, '/' . $denied) !== false) {
                demo_block('The "' . $denied . '" endpoint is disabled in the demo '
                         . '(it modifies data, fetches external feeds, or manages users).');
            }
        }

        if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)
            && !in_array($script, demo_write_allowed_scripts(), true)) {
            demo_block('The demo is read-only; ' . $method . ' requests are not accepted.');
        }

        ob_start('demo_inject_banner');
    }
}

#!/usr/bin/env php
<?php
/**
 * BlockHarbor — demo dataset seeder.
 *
 * Generates a synthetic but plausible dataset for the public demo. Every address
 * comes from the documentation ranges reserved by RFC 5737 (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24) and RFC 3849 (2001:db8::/32), so nothing here
 * can ever route to a real host. CVE identifiers use a 2026-1xxxx block that is
 * not assigned by MITRE.
 *
 * Idempotent: run it on every container start. Only runs when DEMO_MODE=true.
 *
 * Usage: php bin/seed-demo.php [--force]
 */

$root = dirname(__DIR__);
$demo = strtolower(trim((string)getenv('DEMO_MODE'))) === 'true';
$force = in_array('--force', $argv, true);

if (!$demo && !$force) {
    fwrite(STDERR, "seed-demo: DEMO_MODE is not true; refusing to overwrite data (use --force).\n");
    exit(0);
}

mt_srand(20260101); // deterministic dataset across restarts

$TLP     = ['WHITE', 'GREEN', 'AMBER', 'RED'];
$sources = ['spamhaus_drop', 'firehol_level1', 'ci_badguys', 'urlhaus', 'malwarebazaar', 'usom', 'threatfox', 'manual'];
$actors  = ['analyst', 'soc-tier1', 'soc-tier2', 'automation'];
$comments = [
    'SSH brute force against edge firewall',
    'Cobalt Strike beacon C2',
    'Mirai-like telnet scanning',
    'Phishing landing page host',
    'Credential stuffing against VPN portal',
    'Outbound DNS tunnelling detected',
    'Scanning 445/tcp across the perimeter',
    'Known bulletproof hosting range',
    'Emotet distribution node',
    'Exploiting CVE-2026-10077 in the wild',
];

// ------------------------------------------------------------- blacklist.txt --

$lines = [];
for ($i = 0; $i < 140; $i++) {
    $octet = 1 + ($i % 250);
    $net   = ($i % 3 === 0) ? '192.0.2.' : (($i % 3 === 1) ? '198.51.100.' : '203.0.113.');
    $value = $net . $octet;
    $ts    = date('Y-m-d H:i:s', time() - mt_rand(3600, 45 * 86400));
    $ttl   = ($i % 7 === 0) ? date('Y-m-d', time() + mt_rand(3, 60) * 86400) : 'permanent';
    $lines[] = implode('|', [
        $value,
        $comments[$i % count($comments)],
        $ts,
        '',
        ($i % 11 === 0) ? 'SOC-' . (1000 + $i) : '',
        $TLP[$i % 4],
        'ip-src',
        $actors[$i % count($actors)],
        (string)(40 + ($i * 7) % 60),
        $ttl,
    ]);
}
// A few CIDR blocks, as produced by cidr_aggregate.php
foreach (['192.0.2.0/24', '198.51.100.128/25', '203.0.113.64/26'] as $k => $cidr) {
    $lines[] = implode('|', [
        $cidr, 'aggregated from ' . (52 + $k * 9) . ' IPs', date('Y-m-d H:i:s', time() - 86400 * (2 + $k)),
        '', '', 'AMBER', 'cidr', 'automation', '75', 'permanent',
    ]);
}
// Domains and hashes
$domains = ['malicious-update-cdn.example', 'login-verify-portal.example', 'invoice-docs-secure.example',
            'sso-reset-account.example', 'cdn-jquery-min.example'];
foreach ($domains as $k => $d) {
    $lines[] = implode('|', [
        $d, $comments[($k + 3) % count($comments)], date('Y-m-d H:i:s', time() - 86400 * ($k + 1)),
        '', '', $TLP[$k % 4], 'domain', 'analyst', (string)(55 + $k * 8), 'permanent',
    ]);
}
for ($i = 0; $i < 12; $i++) {
    $lines[] = implode('|', [
        md5('blockharbor-demo-sample-' . $i), 'MalwareBazaar recent sample',
        date('Y-m-d H:i:s', time() - 86400 * $i), '', '', 'GREEN', 'md5', 'malwarebazaar', '80', 'permanent',
    ]);
}
file_put_contents("$root/blacklist.txt", implode("\n", $lines) . "\n");

// ------------------------------------------------------------- whitelist.txt --

$wl = [
    '192.0.2.10|' . date('Y-m-d H:i:s', time() - 86400 * 30) . '|analyst|Corporate egress NAT (demo)|GREEN',
    '198.51.100.20|' . date('Y-m-d H:i:s', time() - 86400 * 21) . '|analyst|Branch office uplink (demo)|GREEN',
    '203.0.113.0/24|' . date('Y-m-d H:i:s', time() - 86400 * 14) . '|soc-tier2|Partner VPN range (demo)|AMBER',
    '8.8.8.8|' . date('Y-m-d H:i:s', time() - 86400 * 60) . '|automation|Google Public DNS|WHITE',
];
file_put_contents("$root/whitelist.txt", implode("\n", $wl) . "\n");

// ------------------------------------------------------- blacklist_meta.json --

$meta = [];
foreach (array_slice($lines, 0, 60) as $l) {
    $v = explode('|', $l)[0];
    $picked = array_slice($sources, 0, 1 + (crc32($v) % 4));
    $meta[$v] = [
        'first_seen' => date('Y-m-d H:i:s', time() - mt_rand(10, 60) * 86400),
        'last_seen'  => date('Y-m-d H:i:s', time() - mt_rand(0, 5) * 86400),
        'sources'    => array_values($picked),
        'source_count' => count($picked),
        'sightings'  => crc32($v) % 240,
    ];
}
file_put_contents("$root/blacklist_meta.json", json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// ---------------------------------------------------- feed_health_state.json --

$feeds = [
    'spamhaus_drop'  => ['https://www.spamhaus.org/drop/drop.txt', 1387, 200, true],
    'firehol_level1' => ['https://iplists.firehol.org/files/firehol_level1.netset', 2914, 200, true],
    'ci_badguys'     => ['https://cinsscore.com/list/ci-badguys.txt', 15243, 200, true],
    'urlhaus'        => ['https://urlhaus.abuse.ch/downloads/hostfile/', 8871, 200, true],
    'malwarebazaar'  => ['https://bazaar.abuse.ch/export/txt/md5/recent/', 990, 200, true],
    'usom'           => ['https://www.usom.gov.tr/url-list.txt', 41207, 200, true],
    'stevenblack'    => ['https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 0, 504, false],
    'threatfox'      => ['https://threatfox-api.abuse.ch/api/v1/', 612, 200, true],
];
$fh = [];
foreach ($feeds as $name => [$url, $entries, $status, $ok]) {
    $last = date('Y-m-d H:i:s', time() - mt_rand(600, 7200));
    $fh[$name] = [
        'source' => $name,
        'url' => $url,
        'last_fetch_attempt' => $last,
        'last_fetch_success' => $ok ? $last : date('Y-m-d H:i:s', time() - 3 * 86400),
        'last_http_status' => $status,
        'bytes_received' => $ok ? $entries * mt_rand(14, 22) : 0,
        'parser_ok' => $ok,
        'entries_extracted' => $entries,
        'schema_fingerprint' => substr(hash('sha256', $name), 0, 16),
        'enabled' => true,
        'status' => $ok ? 'OK' : 'FETCH_FAILED',
    ];
}
file_put_contents("$root/feed_health_state.json", json_encode($fh, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// ------------------------------------------------------------- cve_state.json --

$vendors = ['Cisco', 'Fortinet', 'F5', 'Palo Alto', 'Check Point', 'VMware', 'Microsoft', 'Apache'];
$titles = [
    'Authentication bypass in the management interface',
    'Stack overflow in the SSL VPN handler',
    'Improper access control in the REST API',
    'Path traversal in the file upload endpoint',
    'Command injection in the diagnostics CLI',
    'Use-after-free in the packet inspection engine',
    'Missing authorisation on the configuration backup route',
];
$cves = [];
for ($i = 0; $i < 26; $i++) {
    $id = sprintf('CVE-2026-1%04d', 10 + $i * 3);
    $cvss = round(6.0 + (($i * 13) % 40) / 10, 1);
    $cves[$id] = [
        'cve' => $id,
        'vendor' => $vendors[$i % count($vendors)],
        'title' => $titles[$i % count($titles)] . ' (' . $vendors[$i % count($vendors)] . ')',
        'cvss' => $cvss,
        'severity' => $cvss >= 9.0 ? 'CRITICAL' : ($cvss >= 7.0 ? 'HIGH' : 'MEDIUM'),
        'kev' => ($cvss >= 8.5 && $i % 3 === 0),
        'published' => date('Y-m-d', time() - ($i + 1) * 3 * 86400),
        'source' => ($i % 3 === 0) ? 'csaf' : (($i % 3 === 1) ? 'psirt-rss' : 'nvd'),
        'exploited_ips' => ($i % 4 === 0) ? ['198.51.100.' . (30 + $i), '192.0.2.' . (60 + $i)] : [],
    ];
}
file_put_contents("$root/cve_state.json", json_encode($cves, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// ---------------------------------------------------------- pending_ips.json --

$pending = [];
for ($i = 0; $i < 7; $i++) {
    $pending[] = [
        'value' => '198.51.100.' . (200 + $i),
        'type' => 'ip-src',
        'comment' => $comments[$i % count($comments)],
        'requested_by' => $actors[$i % count($actors)],
        'requested_at' => date('Y-m-d H:i:s', time() - $i * 7200),
        'tlp' => $TLP[$i % 4],
        'confidence' => 50 + $i * 5,
    ];
}
file_put_contents("$root/pending_ips.json", json_encode(['pending' => $pending], JSON_PRETTY_PRINT));

// ------------------------------------------------------ customer_assets.json --

$assets = ['customers' => [
    ['name' => 'Northwind Retail (demo)',   'ips' => ['192.0.2.40', '192.0.2.41'],   'vendor_hint' => 'fortinet'],
    ['name' => 'Contoso Manufacturing (demo)', 'ips' => ['198.51.100.70'],           'vendor_hint' => 'cisco'],
    ['name' => 'Fabrikam Logistics (demo)', 'ips' => ['203.0.113.90', '203.0.113.91'], 'vendor_hint' => 'f5'],
], '_updated_at' => gmdate('c')];
file_put_contents("$root/customer_assets.json", json_encode($assets, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

// ------------------------------------------------------------------ users.json --

// The demo account is authenticated by login.php directly, not from this file;
// it is listed here only so the user list in the UI is not empty.
file_put_contents("$root/users.json", json_encode(['users' => [[
    'id' => 'u_demo', 'username' => 'demo', 'role' => 'viewer',
    'email' => 'demo@example.com', 'created_at' => '2026-01-01 00:00:00',
    'last_login' => date('Y-m-d H:i:s'), 'active' => true,
]]], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

// ------------------------------------------------- firewall-facing feed --

// Rebuild the flat feed the same way the application does, so feed_health.php
// and the "consumer URL" panel show a populated feed in the demo.
require_once "$root/lib_firewall_feed.php";
$fw = rebuild_firewall_feed();
fwrite(STDOUT, sprintf(
    "seed-demo: firewall feed %s (%d entries, %d whitelisted out)\n",
    $fw['ok'] ? 'rebuilt' : 'FAILED',
    $fw['count'] ?? 0,
    $fw['subtracted'] ?? 0
));

fwrite(STDOUT, sprintf(
    "seed-demo: %d blacklist entries, %d whitelist, %d feeds, %d CVEs, %d pending, %d customers\n",
    count($lines), count($wl), count($fh), count($cves), count($pending), count($assets['customers'])
));

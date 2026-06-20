<?php
// SPRINT7-T3: Centralized firewall feed rebuild with whitelist subtraction
require_once __DIR__ . '/lib_safe_write.php';

const FW_FEED_DEST = __DIR__ . '/cyberwebeyeosblacklist.txt';
const FW_WHITELIST = __DIR__ . '/whitelist.txt';
const FW_BLACKLIST = __DIR__ . '/blacklist.txt';
const FW_LISTS_DYN = __DIR__ . '/lists_dyn';

/**
 * Rebuild the firewall-facing feed from all enabled blacklist sources,
 * with whitelist subtraction. Atomic write.
 * Returns ['ok'=>bool, 'count'=>int, 'subtracted'=>int, 'error'=>string|null]
 */
function rebuild_firewall_feed(): array {
    // Collect all blacklist entries (values only, dedup via set)
    $set = [];

    // 1. Main blacklist.txt (10-field schema, value is first column)
    if (file_exists(FW_BLACKLIST)) {
        foreach (file(FW_BLACKLIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if ($line[0] === '#') continue;
            $parts = explode('|', $line);
            $v = trim($parts[0] ?? '');
            if ($v !== '') $set[$v] = true;
        }
    }

    // 2. lists_dyn/*.txt (manual user lists)
    if (is_dir(FW_LISTS_DYN)) {
        foreach (glob(FW_LISTS_DYN . '/*.txt') as $lf) {
            foreach (file($lf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if ($line === '' || $line[0] === '#') continue;
                $parts = explode('|', $line);
                $v = trim($parts[0] ?? '');
                if ($v !== '') $set[$v] = true;
            }
        }
    }

    // 3. External feed output files (from sources_config.json, enabled only)
    $src_cfg = __DIR__ . '/sources_config.json';
    if (file_exists($src_cfg)) {
        $cfg = json_decode(file_get_contents($src_cfg), true) ?: [];
        foreach (($cfg['sources'] ?? []) as $s) {
            if (empty($s['enabled'])) continue;
            $of = $s['output_file'] ?? '';
            if (!$of || !file_exists($of)) continue;
            foreach (file($of, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if ($line === '' || $line[0] === '#') continue;
                $v = trim($line);
                if ($v !== '') $set[$v] = true;
            }
        }
    }

    // 4. Whitelist subtraction
    $whitelist_set = [];
    if (file_exists(FW_WHITELIST)) {
        foreach (file(FW_WHITELIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if ($line === '' || $line[0] === '#') continue;
            $parts = explode('|', $line);
            $v = trim($parts[0] ?? '');
            if ($v !== '') $whitelist_set[$v] = true;
        }
    }

    $subtracted = 0;
    foreach (array_keys($whitelist_set) as $w) {
        if (isset($set[$w])) { unset($set[$w]); $subtracted++; }
    }

    // 5. Atomic write
    $values = array_keys($set);
    sort($values);
    $payload = "# Cyberwebeyeos firewall feed — auto-generated " . gmdate('c') . "\n" . implode("\n", $values) . "\n";
    $r = safe_write_atomic(FW_FEED_DEST, $payload);

    if (!$r['ok']) {
        if (function_exists('audit_log_event')) {
            audit_log_event('firewall_feed_rebuild_failed', ['object' => 'cyberwebeyeosblacklist.txt', 'error' => $r['error']]);
        }
        return ['ok' => false, 'count' => 0, 'subtracted' => 0, 'error' => $r['error']];
    }

    if (function_exists('audit_log_event')) {
        audit_log_event('firewall_feed_rebuilt', ['object' => 'cyberwebeyeosblacklist.txt', 'count' => count($values), 'whitelist_subtracted' => $subtracted]);
    }

    return ['ok' => true, 'count' => count($values), 'subtracted' => $subtracted, 'error' => null];
}

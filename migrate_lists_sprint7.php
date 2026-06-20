<?php
// SPRINT7-T4: lists.json schema migration (idempotent)
// Adds kind/side/enabled/type_hint fields; mirrors external sources.
require_once __DIR__ . '/lib_safe_write.php';

const LISTS_FILE = __DIR__ . '/lists.json';
const SOURCES_FILE = __DIR__ . '/sources_config.json';

function migrate_lists(): array {
    $lists = file_exists(LISTS_FILE)
        ? (json_decode(file_get_contents(LISTS_FILE), true) ?: ['lists' => []])
        : ['lists' => []];
    if (!isset($lists['lists']) || !is_array($lists['lists'])) $lists['lists'] = [];

    $by_id = [];
    foreach ($lists['lists'] as $l) {
        if (isset($l['id'])) $by_id[$l['id']] = $l;
    }

    $changes = ['updated' => 0, 'added' => 0];

    // 1. Migrate existing entries to new schema
    foreach ($by_id as $id => &$l) {
        $before = $l;
        $l['kind'] = $l['kind'] ?? ($l['system'] ?? false ? 'system' : 'manual');
        $l['side'] = $l['side'] ?? 'blacklist';
        $l['enabled'] = $l['enabled'] ?? true;
        $l['type_hint'] = $l['type_hint'] ?? ($l['type'] ?? 'mixed');
        $l['default_confidence'] = $l['default_confidence'] ?? null;
        $l['default_tlp'] = $l['default_tlp'] ?? null;
        $l['icon'] = $l['icon'] ?? null;
        $l['order'] = $l['order'] ?? 100;
        if ($l !== $before) $changes['updated']++;
    }
    unset($l);

    // 2. Ensure system-whitelist-all exists
    if (!isset($by_id['system-whitelist-all'])) {
        $by_id['system-whitelist-all'] = [
            'id' => 'system-whitelist-all',
            'name' => 'Tüm Whitelist',
            'slug' => 'whitelist-all',
            'description' => 'Tüm manuel whitelist girdileri — sistem varsayılanı',
            'kind' => 'system',
            'side' => 'whitelist',
            'enabled' => true,
            'type_hint' => 'mixed',
            'file' => __DIR__ . '/whitelist.txt',
            'system' => true,
            'icon' => 'check-circle',
            'order' => 0,
            'created_at' => gmdate('Y-m-d'),
            'default_confidence' => null,
            'default_tlp' => null,
        ];
        $changes['added']++;
    }

    // 3. Mirror enabled external sources from sources_config.json
    if (file_exists(SOURCES_FILE)) {
        $sc = json_decode(file_get_contents(SOURCES_FILE), true) ?: [];
        foreach (($sc['sources'] ?? []) as $s) {
            if (empty($s['enabled'])) continue;
            $feed_id = 'feed-' . ($s['id'] ?? md5($s['name'] ?? ''));
            if (isset($by_id[$feed_id])) continue;
            $slug = strtolower(preg_replace('/[^a-z0-9-]/i', '-', $s['name'] ?? 'feed'));
            $slug = trim(preg_replace('/-+/', '-', $slug), '-');
            $by_id[$feed_id] = [
                'id' => $feed_id,
                'name' => $s['name'] ?? 'Feed',
                'slug' => $slug,
                'description' => $s['description'] ?? '',
                'kind' => 'external',
                'side' => 'blacklist',
                'enabled' => true,
                'type_hint' => $s['target_type'] ?? 'mixed',
                'source_id' => $s['id'] ?? null,
                'file' => $s['output_file'] ?? '',
                'system' => false,
                'icon' => 'globe',
                'order' => 50,
                'default_confidence' => $s['default_confidence'] ?? 60,
                'default_tlp' => 'WHITE',
                'created_at' => gmdate('Y-m-d'),
            ];
            $changes['added']++;
        }
    }

    $lists['lists'] = array_values($by_id);

    $payload = json_encode($lists, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $r = safe_write_atomic(LISTS_FILE, $payload);
    return $r['ok']
        ? ['ok' => true, 'changes' => $changes, 'total' => count($lists['lists'])]
        : ['ok' => false, 'error' => $r['error']];
}

if (php_sapi_name() === 'cli') {
    echo json_encode(migrate_lists(), JSON_PRETTY_PRINT) . "\n";
}

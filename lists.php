<?php
// Cyberwebeyeos Multiple Manual Lists CRUD handler
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';

// R26 (T1.1 RBAC): list CRUD + entry-add yalnız admin
// list_entry_add operator için de mantıklı; ama scope minimal tutup admin verdik. İleride genişletilebilir.
require_role(['admin']);

define('LISTS_JSON', __DIR__ . '/lists.json');
define('LISTS_DIR',  __DIR__ . '/lists_dyn');

function load_lists() {
    if (!file_exists(LISTS_JSON)) return ['lists' => []];
    $d = json_decode(@file_get_contents(LISTS_JSON), true);
    return is_array($d) && isset($d['lists']) ? $d : ['lists' => []];
}
function save_lists(array $data): bool {
    require_once __DIR__ . '/lib_safe_write.php';
    $file = __DIR__ . '/lists.json';
    $payload = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($payload === false) return false;

    // Atomic write: tmp file + rename. Prevents partial writes.
    $r = safe_write_atomic($file, $payload);
    if (!$r['ok'] && function_exists('audit_log_event')) {
        audit_log_event('system', 'save_lists_failed', 'lists.json', ['error' => $r['error']]);
    }
    return $r['ok'];
}
function slugify(string $s): string {
    $s = strtolower(trim($s));
    $s = preg_replace('/[^a-z0-9_-]+/', '-', $s);
    return trim($s, '-') ?: 'list-' . substr(uniqid(), -6);
}

// R71 (S7-T5): Slug validation — ^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$
function valid_list_slug(string $s): bool {
    return (bool)preg_match('/^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/', $s);
}

// R71 (S7-T5): Detect whether response should be JSON (API mode) or redirect (form mode)
function is_api_request(): bool {
    // action= param signals API; form uses list_add/list_delete buttons
    return isset($_POST['action']);
}

function json_error(int $code, string $message): void {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => $message]);
    exit;
}

function json_ok(array $payload = []): void {
    http_response_code(200);
    header('Content-Type: application/json');
    echo json_encode(array_merge(['ok' => true], $payload));
    exit;
}

// R71 (S7-T5): Count non-empty data lines in a list file
function count_list_entries(string $file_path): int {
    if (!file_exists($file_path)) return 0;
    $lines = @file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $count = 0;
    foreach ($lines as $line) {
        $line = trim($line);
        // Skip comment lines
        if ($line === '' || $line[0] === '#') continue;
        $count++;
    }
    return $count;
}

// R71 (S7-T5): Detect entry type from value
function detect_entry_type(string $entry): string {
    // Simple IP detection
    if (filter_var($entry, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'ip';
    if (filter_var($entry, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';
    // CIDR
    if (preg_match('/^[\d.]+\/\d+$/', $entry) || preg_match('/^[0-9a-f:]+\/\d+$/i', $entry)) return 'cidr';
    // URL
    if (preg_match('/^https?:\/\//i', $entry)) return 'url';
    // Domain-like
    if (preg_match('/^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?(\.[a-z]{2,})$/i', $entry)) return 'domain';
    return 'ioc';
}

// R71 (S7-T5): Check if entry type is compatible with list type_hint
function type_hint_matches(string $entry, string $type_hint): bool {
    if ($type_hint === 'mixed' || $type_hint === 'merged' || $type_hint === 'ioc') return true;
    $detected = detect_entry_type($entry);
    $type_hint_lc = strtolower($type_hint);
    if ($type_hint_lc === 'ip' && in_array($detected, ['ip', 'ipv6', 'cidr'], true)) return true;
    if ($type_hint_lc === 'ipv6' && $detected === 'ipv6') return true;
    if ($type_hint_lc === 'cidr' && $detected === 'cidr') return true;
    if ($type_hint_lc === 'domain' && $detected === 'domain') return true;
    if ($type_hint_lc === 'url' && $detected === 'url') return true;
    return $detected === $type_hint_lc;
}

$msg = '';
$redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'cyberwebeyeosblacklistadmin.php#lists';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = load_lists();
    $api = is_api_request();

    // -----------------------------------------------------------------------
    // R71 (S7-T5): API-style action dispatch (action=create|delete|entry_add)
    // -----------------------------------------------------------------------
    if ($api) {
        $action = $_POST['action'];

        // --- action=create ---
        if ($action === 'create') {
            $name = trim($_POST['name'] ?? '');
            $raw_slug = $_POST['slug'] ?? '';
            $slug = $raw_slug !== '' ? $raw_slug : slugify($name);

            // Slug validation
            if (!valid_list_slug($slug)) {
                json_error(400, 'Invalid slug. Must match ^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$. Got: ' . $slug);
            }

            if ($name === '') {
                json_error(400, 'name is required');
            }

            // Slug collision check
            foreach ($data['lists'] as $l) {
                if (($l['slug'] ?? '') === $slug) {
                    json_error(409, 'Slug already exists: ' . $slug);
                }
            }

            // R71 (S7-T5): side param (blacklist|whitelist), default blacklist
            $side = $_POST['side'] ?? 'blacklist';
            if (!in_array($side, ['blacklist', 'whitelist'], true)) {
                $side = 'blacklist';
            }

            // R71 (S7-T5): New field passthrough
            $type_hint = $_POST['type_hint'] ?? 'mixed';
            if (!in_array($type_hint, ['ip', 'ipv6', 'cidr', 'domain', 'url', 'ioc', 'mixed', 'merged'], true)) {
                $type_hint = 'mixed';
            }
            $description = trim($_POST['description'] ?? '');

            // default_confidence: 0-100 clamp
            $default_confidence = null;
            if (isset($_POST['default_confidence']) && $_POST['default_confidence'] !== '') {
                $dc = (int)$_POST['default_confidence'];
                $default_confidence = max(0, min(100, $dc));
            }

            // default_tlp: WHITE|GREEN|AMBER|RED
            $default_tlp = null;
            if (isset($_POST['default_tlp']) && $_POST['default_tlp'] !== '') {
                $tlp = strtoupper($_POST['default_tlp']);
                $default_tlp = in_array($tlp, ['WHITE', 'GREEN', 'AMBER', 'RED'], true) ? $tlp : null;
            }

            $icon = trim($_POST['icon'] ?? '') ?: null;
            $order = isset($_POST['order']) && $_POST['order'] !== '' ? (int)$_POST['order'] : 50;

            if (!is_dir(LISTS_DIR)) @mkdir(LISTS_DIR, 0775, true);
            $file_path = LISTS_DIR . '/' . $slug . '.txt';
            @touch($file_path);
            @chown($file_path, 'www-data');
            @chmod($file_path, 0664);

            $list_entry = [
                'id'                 => 'list_' . uniqid(),
                'name'               => $name,
                'slug'               => $slug,
                'description'        => $description,
                'kind'               => 'manual',
                'side'               => $side,
                'enabled'            => true,
                'type_hint'          => $type_hint,
                'file'               => $file_path,
                'system'             => false,
                'icon'               => $icon,
                'order'              => $order,
                'default_confidence' => $default_confidence,
                'default_tlp'        => $default_tlp,
                'created_at'         => date('Y-m-d H:i:s'),
            ];
            $data['lists'][] = $list_entry;
            save_lists($data);
            audit_log_event('list_create', ['name' => $name, 'slug' => $slug, 'side' => $side, 'type_hint' => $type_hint]);
            json_ok(['slug' => $slug, 'id' => $list_entry['id'], 'message' => 'Liste oluşturuldu: ' . $name]);
        }

        // --- action=delete ---
        if ($action === 'delete') {
            $slug = trim($_POST['slug'] ?? '');
            $id   = trim($_POST['id'] ?? '');

            if ($slug === '' && $id === '') {
                json_error(400, 'slug or id required');
            }

            $found = null;
            $found_idx = null;
            foreach ($data['lists'] as $idx => $l) {
                $match = ($slug !== '' && ($l['slug'] ?? '') === $slug)
                      || ($id   !== '' && ($l['id']   ?? '') === $id);
                if ($match) { $found = $l; $found_idx = $idx; break; }
            }

            if ($found === null) {
                json_error(404, 'Liste bulunamadı');
            }

            // R71 (S7-T5): System list protection
            if (!empty($found['system'])) {
                json_error(403, 'System listesi korumalı (protected), silinemez');
            }

            // R71 (S7-T5): Empty-only delete check
            $file_path = $found['file'] ?? '';
            if ($file_path !== '' && file_exists($file_path)) {
                $entry_count = count_list_entries($file_path);
                if ($entry_count > 0) {
                    json_error(409, 'Liste boş değil (' . $entry_count . ' kayıt). Önce kayıtları sil.');
                }
            }

            // Safe to delete
            array_splice($data['lists'], $found_idx, 1);
            save_lists($data);
            if ($file_path !== '' && strpos($file_path, LISTS_DIR) === 0 && file_exists($file_path)) {
                @unlink($file_path);
            }
            audit_log_event('list_delete', ['name' => $found['name'] ?? '-', 'slug' => $found['slug'] ?? '-']);
            json_ok(['message' => 'Liste silindi: ' . ($found['name'] ?? $slug)]);
        }

        // --- action=entry_add ---
        if ($action === 'entry_add') {
            $slug  = trim($_POST['slug'] ?? '');
            $id    = trim($_POST['list_id'] ?? '');
            $entry = trim($_POST['entry'] ?? '');

            if ($entry === '') {
                json_error(400, 'entry required');
            }

            $found = null;
            foreach ($data['lists'] as $l) {
                $match = ($slug !== '' && ($l['slug'] ?? '') === $slug)
                      || ($id   !== '' && ($l['id']   ?? '') === $id);
                if ($match) { $found = $l; break; }
            }
            if ($found === null) {
                json_error(404, 'Liste bulunamadı');
            }

            // R71 (S7-T5): type_hint warning log — allow add but warn
            $type_hint = $found['type_hint'] ?? 'mixed';
            if (!type_hint_matches($entry, $type_hint)) {
                $detected = detect_entry_type($entry);
                audit_log_event('list_entry_type_mismatch', [
                    'list_slug'  => $found['slug'] ?? '-',
                    'entry'      => $entry,
                    'detected'   => $detected,
                    'type_hint'  => $type_hint,
                    'warning'    => 'Entry type does not match list type_hint; added anyway',
                ]);
            }

            file_put_contents($found['file'], $entry . "\n", FILE_APPEND);
            audit_log_event('list_entry_add', ['slug' => $found['slug'] ?? '-', 'entry' => $entry]);
            json_ok(['message' => 'Eklendi (' . ($found['name'] ?? $slug) . '): ' . $entry]);
        }

        // --- action=rename ---
        if ($action === 'rename') {
            $slug     = trim($_POST['slug'] ?? '');
            $new_name = trim($_POST['new_name'] ?? '');

            if ($slug === '') { json_error(400, 'slug required'); }
            if ($new_name === '') { json_error(400, 'new_name required'); }
            if (mb_strlen($new_name) > 120) { json_error(400, 'new_name too long (max 120)'); }

            $found_idx = null;
            foreach ($data['lists'] as $idx => $l) {
                if (($l['slug'] ?? '') === $slug) { $found_idx = $idx; break; }
            }
            if ($found_idx === null) { json_error(404, 'Liste bulunamadı'); }
            if (!empty($data['lists'][$found_idx]['system'])) {
                json_error(403, 'System listesi korumalı, yeniden adlandırılamaz');
            }

            $old_name = $data['lists'][$found_idx]['name'];
            $data['lists'][$found_idx]['name'] = $new_name;
            save_lists($data);
            audit_log_event('list_rename', ['slug' => $slug, 'old_name' => $old_name, 'new_name' => $new_name]);
            json_ok(['message' => 'Liste yeniden adlandırıldı: ' . $new_name]);
        }

        // --- action=fetch_now ---
        if ($action === 'fetch_now') {
            $slug = trim($_POST['slug'] ?? '');
            if ($slug === '') { json_error(400, 'slug required'); }

            $found = null;
            foreach ($data['lists'] as $l) {
                if (($l['slug'] ?? '') === $slug) { $found = $l; break; }
            }
            if ($found === null) { json_error(404, 'Liste bulunamadı'); }
            if (($found['kind'] ?? 'manual') !== 'external') {
                json_error(400, 'fetch_now yalnızca external listeler için geçerlidir');
            }
            $source_id = $found['source_id'] ?? '';
            if ($source_id === '') { json_error(400, 'Liste için source_id tanımlı değil'); }

            require_once __DIR__ . '/sources_manager.php';
            $result = update_source_now($source_id);
            if (!$result['success']) {
                json_error(500, 'Çekim başarısız: ' . ($result['error'] ?? 'bilinmiyor'));
            }
            audit_log_event('list_fetch_now', ['slug' => $slug, 'source_id' => $source_id, 'count' => $result['count'] ?? 0]);
            json_ok(['message' => 'Çekim tamamlandı', 'count' => $result['count'] ?? 0]);
        }

        // --- action=toggle ---
        if ($action === 'toggle') {
            $slug = trim($_POST['slug'] ?? '');
            if ($slug === '') { json_error(400, 'slug required'); }

            $found     = null;
            $found_idx = null;
            foreach ($data['lists'] as $idx => $l) {
                if (($l['slug'] ?? '') === $slug) { $found = $l; $found_idx = $idx; break; }
            }
            if ($found === null) { json_error(404, 'Liste bulunamadı'); }
            if (!empty($found['system'])) { json_error(403, 'System listesi korumalı, değiştirilemez'); }

            $new_enabled = !($found['enabled'] ?? true);

            if (($found['kind'] ?? 'manual') === 'external') {
                // External lists: sync enabled flag in sources_config.json too
                $source_id = $found['source_id'] ?? '';
                if ($source_id !== '') {
                    require_once __DIR__ . '/sources_manager.php';
                    toggle_source($source_id, $new_enabled);
                }
            }

            // Always update lists.json enabled flag
            $data['lists'][$found_idx]['enabled'] = $new_enabled;
            save_lists($data);
            audit_log_event('list_toggle', ['slug' => $slug, 'enabled' => $new_enabled]);
            json_ok(['enabled' => $new_enabled, 'message' => 'Liste ' . ($new_enabled ? 'etkinleştirildi' : 'devre dışı bırakıldı')]);
        }

        // Unknown action
        json_error(400, 'Unknown action: ' . htmlspecialchars($action));
    }

    // -----------------------------------------------------------------------
    // Legacy form-based handlers (list_add / list_delete / list_entry_add)
    // -----------------------------------------------------------------------
    if (!empty($_POST['list_add'])) {
        $name = trim($_POST['name'] ?? '');
        $slug = slugify($_POST['slug'] ?? $name);
        $type = $_POST['type'] ?? 'merged';
        $desc = trim($_POST['description'] ?? '');

        if ($name === '') {
            $msg = '❌ Liste adı zorunlu';
        } else {
            // Slug çakışması var mı?
            foreach ($data['lists'] as $l) {
                if (($l['slug'] ?? '') === $slug) { $msg = '❌ Bu slug zaten var: ' . $slug; break; }
            }
            if (!$msg) {
                if (!is_dir(LISTS_DIR)) @mkdir(LISTS_DIR, 0775, true);
                $file_path = LISTS_DIR . '/' . $slug . '.txt';
                @touch($file_path);
                @chown($file_path, 'www-data');
                @chmod($file_path, 0664);
                $data['lists'][] = [
                    'id'          => 'list_' . uniqid(),
                    'name'        => $name,
                    'slug'        => $slug,
                    'type'        => in_array($type, ['merged','ip','ipv6','cidr','domain','url','ioc'], true) ? $type : 'merged',
                    'description' => $desc,
                    'file'        => $file_path,
                    'created_at'  => date('Y-m-d H:i:s'),
                    'system'      => false,
                ];
                save_lists($data);
                audit_log_event('list_create', ['name'=>$name, 'slug'=>$slug, 'type'=>$type]);
                $msg = '✅ Liste oluşturuldu: ' . htmlspecialchars($name) . ' (slug: ' . htmlspecialchars($slug) . ')';
            }
        }
    } elseif (!empty($_POST['list_delete'])) {
        $id = $_POST['list_delete'];
        $new = [];
        $removed = null;
        foreach ($data['lists'] as $l) {
            if (($l['id'] ?? '') === $id) {
                if (!empty($l['system'])) { $msg = '❌ System listesi silinemez'; $new[] = $l; continue; }
                $removed = $l;
                if (!empty($l['file']) && strpos($l['file'], LISTS_DIR) === 0 && file_exists($l['file'])) {
                    @unlink($l['file']);
                }
            } else {
                $new[] = $l;
            }
        }
        if ($removed) {
            $data['lists'] = array_values($new);
            save_lists($data);
            audit_log_event('list_delete', ['name'=>$removed['name'] ?? '-', 'id'=>$id]);
            $msg = '✅ Liste silindi: ' . htmlspecialchars($removed['name']);
        } elseif (!$msg) {
            $msg = '❌ Liste bulunamadı';
        }
    } elseif (!empty($_POST['list_entry_add'])) {
        $id = $_POST['list_id'] ?? '';
        $entry = trim($_POST['entry'] ?? '');
        foreach ($data['lists'] as $l) {
            if (($l['id'] ?? '') === $id) {
                if ($entry === '') { $msg = '❌ Boş giriş'; break; }
                // R71 (S7-T5): type_hint warning log
                $type_hint = $l['type_hint'] ?? 'mixed';
                if (!type_hint_matches($entry, $type_hint)) {
                    $detected = detect_entry_type($entry);
                    audit_log_event('list_entry_type_mismatch', [
                        'list_slug' => $l['slug'] ?? '-',
                        'entry'     => $entry,
                        'detected'  => $detected,
                        'type_hint' => $type_hint,
                        'warning'   => 'Entry type does not match list type_hint; added anyway',
                    ]);
                }
                file_put_contents($l['file'], $entry . "\n", FILE_APPEND);
                $msg = '✅ Eklendi (' . htmlspecialchars($l['name']) . '): ' . htmlspecialchars($entry);
                break;
            }
        }
    }

    $_SESSION['message'] = $msg;
    header('Location: ' . $redir);
    exit;
}

// GET: redirect to admin
header('Location: cyberwebeyeosblacklistadmin.php#lists');
exit;

<?php
/**
 * Cyberwebeyeos — Public Feed Health Endpoint (R45 T4.5)
 *
 * Sprint 4 #5. İkincil persona (firewall admin müşterileri) için public status page.
 * Auth gerekmez — sadece feed durumu görünür. Hassas data yok.
 *
 *   GET /feed_health.php         → HTML status board
 *   GET /feed_health.php?json    → JSON (monitoring/Nagios/Zabbix için)
 *
 * Sağlık göstergeleri:
 *   - main feed (cyberwebeyeosblacklist.txt): entry count, last_modified, age
 *   - blacklist.txt: total IoCs, last_modified
 *   - whitelist.txt: count
 *   - Her external source: name, url, last_update, entry_count, file_age, status
 *   - Overall freshness (en eski feed)
 */

require_once __DIR__ . '/ioc_helpers.php';

// Only render HTML/JSON HTTP responses when invoked over HTTP, not when required from CLI
if (php_sapi_name() !== 'cli') {

$BASE = __DIR__;
$JSON_MODE = isset($_GET['json']);

function _file_info(string $path): array {
    if (!file_exists($path)) {
        return ['exists' => false, 'size' => 0, 'mtime' => null, 'age_seconds' => null, 'entries' => 0];
    }
    $entries = 0;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
        if ($l !== '' && $l[0] !== '#') $entries++;
    }
    $mt = filemtime($path);
    return [
        'exists' => true,
        'size' => filesize($path),
        'mtime' => date('Y-m-d H:i:s', $mt),
        'age_seconds' => time() - $mt,
        'entries' => $entries,
    ];
}

function _humanize_age(?int $seconds): string {
    if (is_null($seconds)) return '-';
    if ($seconds < 60) return $seconds . 's';
    if ($seconds < 3600) return floor($seconds/60) . 'dk';
    if ($seconds < 86400) return floor($seconds/3600) . 'sa';
    return floor($seconds/86400) . 'g';
}

function _status_label(?int $age, bool $required_fresh = true): array {
    if (is_null($age)) return ['ok' => false, 'label' => 'YOK', 'color' => '#dc2626'];
    if ($age < 7200) return ['ok' => true,  'label' => 'TAZE', 'color' => '#10b981']; // <2h
    if ($age < 86400) return ['ok' => true, 'label' => 'TAMAM', 'color' => '#0ea5e9']; // <24h
    if ($age < 172800) return ['ok' => $required_fresh ? false : true, 'label' => 'ESKİ', 'color' => '#f59e0b']; // <48h
    return ['ok' => false, 'label' => 'BAYAT', 'color' => '#dc2626'];
}

// --- Main feed (public consumption) ---
$main = _file_info($BASE . '/cyberwebeyeosblacklist.txt');
$bl = _file_info($BASE . '/blacklist.txt');
$wl = _file_info($BASE . '/whitelist.txt');
$pending = @json_decode(@file_get_contents($BASE . '/pending_ips.json'), true);
$pending_count = count($pending['pending_ips'] ?? []);

// --- External sources ---
$sources_cfg = @json_decode(@file_get_contents($BASE . '/sources_config.json'), true);
$sources = [];
foreach (($sources_cfg['sources'] ?? []) as $s) {
    $of = $s['output_file'] ?? '';
    $info = $of ? _file_info($of) : ['exists'=>false,'size'=>0,'mtime'=>null,'age_seconds'=>null,'entries'=>0];
    $sources[] = [
        'id' => $s['id'] ?? '',
        'name' => $s['name'] ?? '?',
        'url' => $s['url'] ?? '',
        'enabled' => !empty($s['enabled']),
        'update_interval_sec' => (int)($s['update_interval'] ?? 0),
        'last_update_config' => $s['last_update'] ?? null,
        'entry_count' => $info['entries'],
        'file_mtime' => $info['mtime'],
        'file_age_seconds' => $info['age_seconds'],
        'file_size' => $info['size'],
        'config_status' => $s['last_status'] ?? 'unknown',
    ];
}

// --- Overall freshness ---
$ages_to_check = [$main['age_seconds']];
foreach ($sources as $s) if ($s['enabled'] && !is_null($s['file_age_seconds'])) $ages_to_check[] = $s['file_age_seconds'];
$oldest = !empty(array_filter($ages_to_check, fn($a) => !is_null($a))) ? max(array_filter($ages_to_check, fn($a) => !is_null($a))) : null;

$overall = _status_label($oldest);

if ($JSON_MODE) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: max-age=60');
    echo json_encode([
        'ok' => $overall['ok'],
        'overall_status' => $overall['label'],
        'generated_at' => date('Y-m-d H:i:s'),
        'main_feed' => [
            'url' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'host') . '/blacklist/cyberwebeyeos/cyberwebeyeosblacklist.txt',
            'entries' => $main['entries'],
            'size_bytes' => $main['size'],
            'last_modified' => $main['mtime'],
            'age_seconds' => $main['age_seconds'],
        ],
        'blacklist' => $bl,
        'whitelist' => $wl,
        'pending_count' => $pending_count,
        'sources' => $sources,
        'oldest_age_seconds' => $oldest,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// --- HTML status page ---
header('Content-Type: text/html; charset=utf-8');
$main_status = _status_label($main['age_seconds']);
$bl_status = _status_label($bl['age_seconds']);
$feed_url = 'https://' . ($_SERVER['HTTP_HOST'] ?? 'host') . '/blacklist/cyberwebeyeos/cyberwebeyeosblacklist.txt';
?><!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyberwebeyeos Blacklist Feed — Health</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#f1f5f9;color:#0f172a;min-height:100vh;padding:24px;}
  .container{max-width:1100px;margin:0 auto;}
  h1{font-size:24px;margin-bottom:4px;color:#0f172a;letter-spacing:-.01em;}
  .sub{color:#64748b;font-size:13px;margin-bottom:20px;}
  .overall{display:flex;align-items:center;gap:14px;padding:20px;background:#fff;border-radius:12px;
           border:1px solid #e2e8f0;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.04);}
  .pill{display:inline-block;padding:6px 14px;border-radius:999px;color:#fff;font-weight:700;font-size:14px;letter-spacing:.04em;}
  .card{background:#fff;border-radius:12px;border:1px solid #e2e8f0;margin-bottom:16px;overflow:hidden;}
  .card-head{padding:14px 18px;background:#f8fafc;border-bottom:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center;}
  .card-head h2{font-size:14px;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.04em;}
  .card-body{padding:18px;}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;}
  .kpi{padding:12px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;}
  .kpi-lbl{font-size:11px;text-transform:uppercase;color:#64748b;letter-spacing:.04em;}
  .kpi-val{font-size:22px;font-weight:700;color:#0f172a;margin-top:4px;font-variant-numeric:tabular-nums;}
  table{width:100%;border-collapse:collapse;font-size:13px;}
  th{text-align:left;padding:10px 14px;background:#f8fafc;font-size:11px;text-transform:uppercase;color:#64748b;letter-spacing:.04em;border-bottom:1px solid #e2e8f0;}
  td{padding:10px 14px;border-bottom:1px solid #f1f5f9;}
  td.num{text-align:right;font-variant-numeric:tabular-nums;font-family:'Fira Code',Consolas,monospace;font-size:12px;}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;}
  code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-family:'Fira Code',Consolas,monospace;font-size:12px;}
  a{color:#0ea5e9;text-decoration:none;}
  a:hover{text-decoration:underline;}
  footer{margin-top:24px;text-align:center;color:#94a3b8;font-size:12px;}
  .pull-cmd{margin-top:14px;padding:14px;background:#0f172a;color:#e2e8f0;border-radius:8px;font-family:'Fira Code',Consolas,monospace;font-size:12px;line-height:1.6;overflow-x:auto;}
  .pull-cmd .c{color:#10b981;}
</style>
</head>
<body>
<div class="container">
  <h1>🛡 Cyberwebeyeos Blacklist Feed — Health</h1>
  <p class="sub">Threat Intelligence Platform — feed durumu (public). Generated: <code><?= date('Y-m-d H:i:s') ?></code></p>

  <div class="overall">
    <div class="pill" style="background:<?= $overall['color'] ?>;"><?= $overall['label'] ?></div>
    <div>
      <div style="font-size:15px;font-weight:600;">Genel Durum</div>
      <div style="color:#64748b;font-size:13px;">En eski aktif feed: <?= _humanize_age($oldest) ?> önce güncellendi</div>
    </div>
  </div>

  <!-- Main feed -->
  <div class="card">
    <div class="card-head">
      <h2>🔥 Public Feed (Firewall Consumption)</h2>
      <span class="badge" style="background:<?= $main_status['color'] ?>;color:#fff;"><?= $main_status['label'] ?></span>
    </div>
    <div class="card-body">
      <div class="grid">
        <div class="kpi"><div class="kpi-lbl">Toplam IoC</div><div class="kpi-val"><?= number_format($main['entries']) ?></div></div>
        <div class="kpi"><div class="kpi-lbl">Boyut</div><div class="kpi-val"><?= round($main['size']/1024, 1) ?> <span style="font-size:14px;color:#64748b;">KB</span></div></div>
        <div class="kpi"><div class="kpi-lbl">Son güncelleme</div><div class="kpi-val" style="font-size:14px;"><?= htmlspecialchars($main['mtime'] ?? '-') ?></div></div>
        <div class="kpi"><div class="kpi-lbl">Yaş</div><div class="kpi-val" style="color:<?= $main_status['color'] ?>;"><?= _humanize_age($main['age_seconds']) ?></div></div>
      </div>
      <div class="pull-cmd">
<span class="c"># Çekme komutu (firewall/cron)</span>
curl -sS <?= htmlspecialchars($feed_url) ?> -o /etc/firewall/cwe-blacklist.txt
      </div>
    </div>
  </div>

  <!-- External sources -->
  <div class="card">
    <div class="card-head">
      <h2>📡 External Feed Kaynakları</h2>
      <span style="font-size:12px;color:#64748b;"><?= count(array_filter($sources, fn($s) => $s['enabled'])) ?> aktif / <?= count($sources) ?> toplam</span>
    </div>
    <table>
      <thead><tr><th>Kaynak</th><th class="num">IoC</th><th>Durum</th><th>Yaş</th><th>Son güncelleme</th></tr></thead>
      <tbody>
      <?php foreach ($sources as $s):
        $s_status = $s['enabled'] ? _status_label($s['file_age_seconds']) : ['label'=>'PASİF','color'=>'#94a3b8','ok'=>true];
      ?>
        <tr>
          <td>
            <b><?= htmlspecialchars($s['name']) ?></b>
            <?php if ($s['url']): ?><br><a href="<?= htmlspecialchars($s['url']) ?>" target="_blank" rel="noopener" style="font-size:11px;color:#94a3b8;"><?= htmlspecialchars($s['url']) ?></a><?php endif; ?>
          </td>
          <td class="num"><?= number_format($s['entry_count']) ?></td>
          <td><span class="badge" style="background:<?= $s_status['color'] ?>;color:#fff;"><?= $s_status['label'] ?></span></td>
          <td style="font-size:12px;color:#475569;"><?= $s['enabled'] ? _humanize_age($s['file_age_seconds']) : '-' ?></td>
          <td style="font-size:11.5px;color:#64748b;"><?= htmlspecialchars($s['file_mtime'] ?? '-') ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <!-- Stats -->
  <div class="card">
    <div class="card-head"><h2>📊 İç İstatistik</h2></div>
    <div class="card-body">
      <div class="grid">
        <div class="kpi"><div class="kpi-lbl">Manual Blacklist</div><div class="kpi-val"><?= number_format($bl['entries']) ?></div></div>
        <div class="kpi"><div class="kpi-lbl">Whitelist</div><div class="kpi-val"><?= number_format($wl['entries']) ?></div></div>
        <div class="kpi"><div class="kpi-lbl">Pending Onay</div><div class="kpi-val"><?= number_format($pending_count) ?></div></div>
      </div>
    </div>
  </div>

  <footer>
    <p>API/Monitoring: <a href="?json">JSON endpoint</a> · Admin: <a href="/blacklist/cyberwebeyeos/">Yönetim Paneli</a></p>
    <p>© <?= date('Y') ?> Cyberwebeyeos — Threat Intelligence Platform</p>
  </footer>
</div>
</body>
</html>
<?php
} // end if (php_sapi_name() !== 'cli')

// ============================================================
// SPRINT6-B4: Heartbeat + schema-fingerprint + auto-disable
// ============================================================

const FEED_HEALTH_STATE = __DIR__ . '/feed_health_state.json';
const FEED_HEALTH_WARN_DAYS = 14;
const FEED_HEALTH_DISABLE_DAYS = 30;

function feed_health_state_load(): array {
    if (!file_exists(FEED_HEALTH_STATE)) return [];
    $s = file_get_contents(FEED_HEALTH_STATE);
    $j = json_decode($s, true);
    return is_array($j) ? $j : [];
}

function feed_health_state_save(array $state): void {
    $fh = fopen(FEED_HEALTH_STATE, 'c+');
    if (!$fh || !flock($fh, LOCK_EX)) {
        if ($fh) fclose($fh);
        return; // cannot write safely; caller already returned the in-memory state
    }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($state, JSON_PRETTY_PRINT));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
}

function feed_health_fingerprint(string $body, string $format = 'json'): string {
    if ($format === 'json') {
        $j = json_decode($body, true);
        if (!is_array($j)) return md5('INVALID');
        $keys = array_keys($j);
        sort($keys);
        return md5(implode(',', $keys));
    }
    if ($format === 'rss' || $format === 'xml') {
        $xml = @simplexml_load_string($body);
        if ($xml === false) return md5('INVALID');
        $children = [];
        foreach ($xml->children() as $name => $child) {
            $children[] = (string)$name;
            // One level deeper for RSS containers (e.g. channel > item fields)
            foreach ($child->children() as $sub => $_) {
                $children[] = $name . '.' . $sub;
            }
        }
        sort($children);
        return md5(implode(',', array_unique($children)));
    }
    return md5(substr($body, 0, 200));
}

/**
 * Record a fetch attempt. Returns true if ingestion should proceed,
 * false if SCHEMA_DRIFT or DISABLED.
 *
 * $event keys:
 *   url, http_status, bytes_received, parser_ok, entries_extracted,
 *   raw_body (used for fingerprint), format ('json'|'rss'|'xml')
 */
function feed_health_heartbeat(string $source, array $event): bool {
    // I1: Hold a single exclusive lock for the entire read-modify-write cycle
    // to prevent TOCTOU races when multiple fetchers run concurrently.
    $fh = fopen(FEED_HEALTH_STATE, 'c+');
    if (!$fh || !flock($fh, LOCK_EX)) {
        if ($fh) fclose($fh);
        return false; // cannot acquire lock, fail closed
    }

    $raw = stream_get_contents($fh);
    $state = $raw ? (json_decode($raw, true) ?: []) : [];
    if (!is_array($state)) $state = [];

    $prev = $state[$source] ?? [];
    $now = gmdate('c');
    $success = ($event['http_status'] ?? 0) === 200 && ($event['parser_ok'] ?? false);
    $fmt = $event['format'] ?? 'json';
    $fp_new = feed_health_fingerprint($event['raw_body'] ?? '', $fmt);

    $entry = [
        'source' => $source,
        'url' => $event['url'] ?? ($prev['url'] ?? ''),
        'last_fetch_attempt' => $now,
        'last_fetch_success' => $success ? $now : ($prev['last_fetch_success'] ?? ''),
        'last_http_status' => $event['http_status'] ?? 0,
        'bytes_received' => $event['bytes_received'] ?? 0,
        'parser_ok' => (bool)($event['parser_ok'] ?? false),
        'entries_extracted' => (int)($event['entries_extracted'] ?? 0),
        'schema_fingerprint' => $fp_new,
        'enabled' => $prev['enabled'] ?? true,
        'status' => 'OK',
    ];

    // Schema drift detection
    $fp_prev = $prev['schema_fingerprint'] ?? null;
    if ($fp_prev && $fp_prev !== $fp_new && $success) {
        $entry['status'] = 'SCHEMA_DRIFT';
        $entry['drift_at'] = $now;
        $entry['drift_prev_fp'] = $fp_prev;
        $state[$source] = $entry;
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode($state, JSON_PRETTY_PRINT));
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
        if (function_exists('audit_log_event')) {
            audit_log_event('feed_schema_drift', ['object' => $source, 'prev' => $fp_prev, 'new' => $fp_new]);
        }
        return false;
    }

    // C1: Auto-disable on prolonged failure — only check when the CURRENT fetch failed.
    // Using $prev['last_fetch_success'] on a recovery fetch would incorrectly fire
    // AUTO_DISABLED even though $entry['last_fetch_success'] was just updated to $now.
    if (!$success) {
        $last_ok = $prev['last_fetch_success'] ?? '';
        if ($last_ok) {
            $days_since = (time() - strtotime($last_ok)) / 86400;
            if ($days_since >= FEED_HEALTH_DISABLE_DAYS && $entry['enabled']) {
                $entry['enabled'] = false;
                $entry['status'] = 'AUTO_DISABLED';
                if (function_exists('audit_log_event')) {
                    audit_log_event('feed_auto_disable', ['object' => $source, 'days_since_success' => $days_since]);
                }
            } elseif ($days_since >= FEED_HEALTH_WARN_DAYS && $entry['status'] === 'OK') {
                $entry['status'] = 'STALE_WARN';
            }
        }
    }

    $state[$source] = $entry;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($state, JSON_PRETTY_PRINT));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);

    return $entry['enabled'] && $entry['status'] !== 'SCHEMA_DRIFT';
}

function feed_health_status_all(): array {
    return feed_health_state_load();
}

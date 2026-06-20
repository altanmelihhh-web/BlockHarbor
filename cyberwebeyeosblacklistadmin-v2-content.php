<?php
/**
 * cyberwebeyeosblacklistadmin-v2.php  —  R89-v2
 * --------------------------------------------------------------------------
 * Sıfırdan yeniden tasarlanmış paralel Blacklist admin sayfası.
 *
 * Kök fikir (CLS=0 garantisi):
 *   html, body { overflow: hidden }      → sayfa boyu DAİMA 100vh, dış scroll yok
 *   .content   { overflow: auto }        → tek scrollable bölge içeride
 *   contain: strict                      → layout/paint/size izolasyonu
 *   grid-template-rows: var(--topbar) var(--kpi) 1fr  → satır yükseklikleri sabit
 *
 * Sonuç: sayfa toplam boyu hiçbir koşulda değişmez → layout shift kategorik
 * imkansız. Conditional banner'lar `.content` içinde kalır, dış kabuğu
 * hiçbir zaman etkilemez.
 *
 * Sınırlar (sade scope):
 *   - Sadece Blacklist sekmesi (whitelist/pending/catalog v1'de kalır).
 *   - Sadece liste tablosu + sidebar list picker + 4 KPI + inline manuel ekle.
 *   - Drawer/modal yok — manuel ekle inline `.content` içinde.
 *   - 3rd-party framework yok (vanilla fetch + native HTML/CSS).
 *
 * v1 dokunulmadı; paralel test için. Beğenilirse v1 deprecate edilir.
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_once __DIR__ . '/ioc_helpers.php';
require_once __DIR__ . '/lib_firewall_feed.php';

// RBAC: POST = write mutation → admin/operator gerekli.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_role(['admin','operator']);
}

if (!isset($_SESSION['message'])) $_SESSION['message'] = '';

// ---------------------------------------------------------------------------
// Query / state
// ---------------------------------------------------------------------------
$list_filter = isset($_GET['list']) && $_GET['list'] !== '' ? trim($_GET['list']) : 'all';
$search      = isset($_GET['q'])    ? trim($_GET['q']) : '';
$page        = max(1, (int)($_GET['page'] ?? 1));
$per_page    = 25;
$is_fragment = isset($_GET['fragment']) && $_GET['fragment'] === '1';

// ---------------------------------------------------------------------------
// lists.json okuma + 3-section grupla
// ---------------------------------------------------------------------------
function v2_load_lists(): array {
    $p = __DIR__ . '/lists.json';
    if (!is_file($p)) return [];
    $j = json_decode(@file_get_contents($p), true);
    return is_array($j['lists'] ?? null) ? $j['lists'] : [];
}
function v2_groups_blacklist(array $all): array {
    $g = ['system' => [], 'manual' => [], 'external' => [], 'dynamic' => []];
    foreach ($all as $l) {
        if (($l['side'] ?? 'blacklist') !== 'blacklist') continue;
        if (empty($l['enabled']) && empty($l['system'])) continue;
        $k = $l['kind'] ?? 'manual';
        if (isset($g[$k])) $g[$k][] = $l;
    }
    return $g;
}
function v2_resolve_list(string $filter, array $all): array {
    if ($filter === 'all' || $filter === 'Manuel' || $filter === 'manual') {
        return ['kind' => 'system', 'name' => 'Tümü Manuel',
                'file' => __DIR__ . '/blacklist.txt', 'writable' => true];
    }
    if ($filter === 'all-external') {
        return ['kind' => 'external', 'name' => 'Tümü Dış Kaynak',
                'file' => '', 'writable' => false, 'aggregate' => true];
    }
    foreach ($all as $l) {
        if (($l['slug'] ?? '') === $filter || ($l['id'] ?? '') === $filter) {
            $kind = $l['kind'] ?? 'manual';
            return [
                'kind' => $kind,
                'name' => $l['name'] ?? $filter,
                'file' => $l['file'] ?? '',
                'writable' => in_array($kind, ['manual','system'], true),
            ];
        }
    }
    // fallback
    return ['kind' => 'system', 'name' => 'Tümü Manuel',
            'file' => __DIR__ . '/blacklist.txt', 'writable' => true];
}

$all_lists  = v2_load_lists();
$groups     = v2_groups_blacklist($all_lists);
$active     = v2_resolve_list($list_filter, $all_lists);

// ---------------------------------------------------------------------------
// POST handlers (v2 kendi içinde — v1'e dokunmaz, redirect döner)
// ---------------------------------------------------------------------------
function v2_redirect_self(string $extra = ''): void {
    $u = $_SERVER['PHP_SELF'];
    if ($extra !== '') $u .= '?' . ltrim($extra, '?');
    header('Location: ' . $u);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['v2_sync'])) {
    $r = rebuild_firewall_feed();
    $_SESSION['message'] = $r['ok']
        ? "Feed yeniden oluşturuldu: {$r['count']} kayıt ({$r['subtracted']} whitelist çıkarıldı)."
        : "Feed hatası: " . htmlspecialchars($r['error'] ?? 'bilinmeyen');
    v2_redirect_self('list=' . urlencode($list_filter));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['v2_add'])) {
    if (!$active['writable']) {
        $_SESSION['message'] = "Bu listeye yazma yapılamaz (kind=" . htmlspecialchars($active['kind']) . ").";
        v2_redirect_self('list=' . urlencode($list_filter));
    }
    $raw    = trim($_POST['entries'] ?? '');
    $comment= trim($_POST['comment'] ?? '');
    $added = 0; $skipped = 0; $errs = [];
    if ($raw === '') {
        $_SESSION['message'] = "Giriş boş.";
        v2_redirect_self('list=' . urlencode($list_filter));
    }
    $lines = preg_split('/[\r\n,]+/', $raw);
    $file  = $active['file'];
    if (!is_file($file)) @touch($file);
    foreach ($lines as $line) {
        $val = trim($line);
        if ($val === '' || $val[0] === '#') continue;
        $type = cwe_detect_type($val);
        if ($type === 'unknown') { $skipped++; $errs[] = $val; continue; }
        // Hızlı IP geçerliliği — sadece IP/CIDR için (domain/url/hash open-form).
        if (in_array($type, ['ip-src','ip-dst','cidr'], true)) {
            $ip = (strpos($val,'/') !== false) ? explode('/', $val)[0] : $val;
            if (!filter_var($ip, FILTER_VALIDATE_IP)) { $skipped++; $errs[] = $val; continue; }
            if (in_array($type, ['ip-src','ip-dst'], true) && strpos($val,'/') === false) $val .= '/32';
        }
        $entry = [
            'value'       => $val,
            'comment'     => $comment,
            'date'        => date('Y-m-d H:i:s'),
            'tlp'         => 'WHITE',
            'type'        => $type,
            'added_by'    => 'v2:' . cwe_current_user(),
            'confidence'  => 75,
            'valid_until' => cwe_default_valid_until(90),
        ];
        if (@file_put_contents($file, cwe_format_blacklist_entry($entry) . "\n", FILE_APPEND | LOCK_EX) !== false) {
            $added++;
        } else { $skipped++; $errs[] = $val; }
    }
    if (function_exists('audit_log_event')) {
        audit_log_event('v2_manual_add', ['list'=>$list_filter, 'added'=>$added, 'skipped'=>$skipped]);
    }
    $msg = "✓ <strong>{$added}</strong> kayıt eklendi";
    if ($skipped > 0) {
        $msg .= ", {$skipped} atlandı";
        if (!empty($errs)) $msg .= " (ilk: " . htmlspecialchars(implode(', ', array_slice($errs, 0, 3))) . ")";
    }
    $_SESSION['message'] = $msg;
    v2_redirect_self('list=' . urlencode($list_filter));
}

// ---------------------------------------------------------------------------
// KPI sayıları (v1 cache fonksiyonu mevcut değilse basit fallback)
// ---------------------------------------------------------------------------
function v2_count(string $f): int {
    if (function_exists('_cwe_cached_count')) return _cwe_cached_count($f);
    if (!is_file($f)) return 0;
    $n = 0; $fh = @fopen($f, 'r'); if (!$fh) return 0;
    while (($l = fgets($fh)) !== false) { $t = trim($l); if ($t !== '' && $t[0] !== '#') $n++; }
    fclose($fh); return $n;
}
$kpi_total    = v2_count(__DIR__ . '/cyberwebeyeosblacklist.txt');
$kpi_manuel   = v2_count(__DIR__ . '/blacklist.txt');
$kpi_external = 0;
foreach ($groups['external'] as $l) { $kpi_external += v2_count($l['file'] ?? ''); }
$kpi_feeds    = count($groups['external']);

// ---------------------------------------------------------------------------
// Aktif listenin satırlarını oku (search + paginate)
// ---------------------------------------------------------------------------
function v2_read_entries(string $file, string $search, int $page, int $per_page): array {
    if (!is_file($file)) return ['rows'=>[], 'total'=>0];
    $rows = [];
    $fh = fopen($file, 'r');
    if (!$fh) return ['rows'=>[], 'total'=>0];
    while (($line = fgets($fh)) !== false) {
        $t = trim($line);
        if ($t === '' || $t[0] === '#') continue;
        if ($search !== '' && stripos($t, $search) === false) continue;
        $rows[] = cwe_parse_blacklist_entry($line);
    }
    fclose($fh);
    $total = count($rows);
    $offset = ($page - 1) * $per_page;
    $rows = array_slice($rows, $offset, $per_page);
    return ['rows'=>$rows, 'total'=>$total];
}

if ($active['aggregate'] ?? false) {
    // Dış kaynak özet — sadece liste isimleri + counts (satır okuma yok, RAM güvenli)
    $entries = ['rows'=>[], 'total'=>0];
} else {
    $entries = v2_read_entries($active['file'], $search, $page, $per_page);
}
$total_pages = max(1, (int)ceil($entries['total'] / $per_page));

// ===========================================================================
// Render-only helper — hem full hem fragment için tek yer.
// ===========================================================================
function v2_render_content(array $active, array $entries, int $page, int $total_pages,
                           string $list_filter, string $search, array $groups): void {
    $msg = $_SESSION['message'] ?? '';
    if ($msg !== '') unset($_SESSION['message']);
    ?>
    <?php if ($msg !== ''): ?>
      <div class="toast" role="status"><?= $msg /* zaten escape edilmiş */ ?>
        <button type="button" class="toast-x" aria-label="Kapat" onclick="this.parentElement.remove()">&times;</button>
      </div>
    <?php endif; ?>

    <header class="card-head">
      <h2>
        <?= htmlspecialchars($active['name']) ?>
        <span class="kind-tag kind-<?= htmlspecialchars($active['kind']) ?>">
          <?= htmlspecialchars(match($active['kind']) {
            'system'   => 'Manuel (Sistem)',
            'manual'   => 'Manuel',
            'external' => 'Dış Kaynak',
            'dynamic'  => 'Akıllı Liste',
            default    => $active['kind'],
          }) ?>
        </span>
      </h2>
      <div class="card-actions">
        <form method="get" class="search-form">
          <input type="hidden" name="list" value="<?= htmlspecialchars($list_filter) ?>">
          <input type="search" name="q" value="<?= htmlspecialchars($search) ?>"
                 placeholder="IP/domain ara…" aria-label="Arama">
        </form>
        <form method="post" style="display:inline;">
          <button type="submit" name="v2_sync" value="1" class="btn"
                  title="Manuel listeyi firewall feed'ine birleştir">Senkronize Et</button>
        </form>
        <a class="btn" href="cyberwebeyeosblacklist.txt" target="_blank">Feed.txt</a>
      </div>
    </header>

    <?php if (!empty($active['aggregate'])): ?>
      <section class="external-summary">
        <h3>Dış kaynak listeleri</h3>
        <ul class="ext-list">
          <?php foreach ($groups['external'] as $l): ?>
            <li>
              <a href="?list=<?= urlencode($l['slug'] ?? '') ?>">
                <?= htmlspecialchars($l['name'] ?? '') ?>
              </a>
              <span class="ext-count tabular"><?= number_format(v2_count($l['file'] ?? ''), 0, ',', '.') ?></span>
            </li>
          <?php endforeach; ?>
          <?php if (empty($groups['external'])): ?>
            <li class="ext-empty">Henüz dış kaynak yok.</li>
          <?php endif; ?>
        </ul>
      </section>
    <?php else: ?>

      <?php if ($active['writable']): ?>
        <section class="add-form">
          <details>
            <summary>+ Manuel ekleme (IP / CIDR / Domain / URL — her satır bir kayıt)</summary>
            <form method="post" class="add-form-body">
              <textarea name="entries" rows="3" required
                placeholder="192.0.2.1&#10;malware.example.com&#10;10.0.0.0/24"></textarea>
              <input type="text" name="comment" placeholder="Yorum (opsiyonel)">
              <button type="submit" name="v2_add" value="1" class="btn btn-primary">Ekle</button>
              <span class="add-help">TLP=WHITE · güven=75 · 90 gün geçerli (defaults)</span>
            </form>
          </details>
        </section>
      <?php endif; ?>

      <table class="data-table">
        <colgroup>
          <col style="width:38%">
          <col style="width:10%">
          <col style="width:22%">
          <col style="width:10%">
          <col style="width:10%">
          <col style="width:10%">
        </colgroup>
        <thead>
          <tr>
            <th>Değer</th>
            <th>Tip</th>
            <th>Yorum</th>
            <th>TLP</th>
            <th>Güven</th>
            <th>Tarih</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($entries['rows'])): ?>
            <tr class="empty-row"><td colspan="6">Bu listede kayıt yok.</td></tr>
          <?php else: foreach ($entries['rows'] as $r): ?>
            <tr>
              <td class="mono"><?= htmlspecialchars($r['value']) ?></td>
              <td><?= htmlspecialchars($r['type']) ?></td>
              <td><?= htmlspecialchars($r['comment']) ?></td>
              <td><span class="tlp tlp-<?= strtolower($r['tlp']) ?>"><?= htmlspecialchars($r['tlp']) ?></span></td>
              <td class="tabular"><?= (int)$r['confidence'] ?></td>
              <td class="mono"><?= htmlspecialchars(substr($r['date'], 0, 10)) ?></td>
            </tr>
          <?php endforeach; endif; ?>
        </tbody>
      </table>

      <?php if ($total_pages > 1): ?>
        <nav class="pager" aria-label="Sayfa">
          <?php if ($page > 1): ?>
            <a href="?list=<?= urlencode($list_filter) ?>&q=<?= urlencode($search) ?>&page=<?= $page-1 ?>">&laquo; Önceki</a>
          <?php endif; ?>
          <span class="pager-info">Sayfa <?= $page ?> / <?= $total_pages ?> · toplam <?= number_format($entries['total'], 0, ',', '.') ?> kayıt</span>
          <?php if ($page < $total_pages): ?>
            <a href="?list=<?= urlencode($list_filter) ?>&q=<?= urlencode($search) ?>&page=<?= $page+1 ?>">Sonraki &raquo;</a>
          <?php endif; ?>
        </nav>
      <?php endif; ?>
    <?php endif; ?>
    <?php
}

// Fragment yanıtı: sadece content blob
if ($is_fragment) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    v2_render_content($active, $entries, $page, $total_pages, $list_filter, $search, $groups);
    exit;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Blacklist v2 — <?= htmlspecialchars($active['name']) ?></title>
<style>
/* ===== Tokens ===== */
:root{
  --sidebar-w: 260px;
  --topbar-h:  60px;
  --kpi-h:     140px;
  --brand:     #1971c2;
  --brand-d:   #15518a;
  --bg:        #f4f6fa;
  --surface:   #ffffff;
  --border:    #dce3ea;
  --text:      #1a2332;
  --muted:     #5a6a7e;
  --slate-50:  #f7f9fc;
  --slate-900: #182433;
  --danger:    #c92a2a;
  --success:   #2f9e44;
  --warning:   #e67700;
}

/* ===== Sıfır-shift garantisi =====
   html, body { overflow: hidden } → sayfa toplam boyu DAİMA 100vh.
   .content   { overflow: auto }   → tek scrollable bölge içeride.
   contain: strict → layout/paint/size izolasyonu (CLS impossible). */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;overflow:hidden;}
body{
  font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
  font-size: 14px;
  line-height: 1.5;
  color: var(--text);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
}
/* Inter fallback metric override — font swap shift = 0 */
@font-face{
  font-family:'Inter Fallback';
  src: local('Arial'), local('Helvetica'), local('sans-serif');
  size-adjust:107%; ascent-override:90%; descent-override:22%; line-gap-override:0%;
}
a{color:inherit;text-decoration:none;}
button{font:inherit;color:inherit;background:none;border:none;cursor:pointer;}
.tabular{font-variant-numeric:tabular-nums;}
.mono{font-family:'SF Mono','Fira Code',Menlo,Consolas,monospace;font-size:.92em;}

/* ===== Grid kabuğu (fixed dimensions) ===== */
.app{
  display: grid;
  grid-template-rows: var(--topbar-h) 1fr;
  grid-template-columns: var(--sidebar-w) 1fr;
  height: 100vh;
}
.topbar{
  grid-column: 1 / -1; grid-row: 1;
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px;
  background: var(--slate-900); color: #fff;
  border-bottom: 1px solid #000;
}
.topbar .brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:-.01em;}
.topbar .brand-logo{
  width:34px;height:34px;border-radius:8px;background:var(--brand);
  display:flex;align-items:center;justify-content:center;font-size:14px;
}
.topbar .topbar-right{display:flex;align-items:center;gap:14px;font-size:12.5px;color:#cbd5e1;}
.topbar .topbar-right .v2-tag{
  padding:3px 8px;background:var(--brand);color:#fff;border-radius:99px;font-size:11px;font-weight:600;
}
.topbar .topbar-right a{color:#cbd5e1;text-decoration:underline;}

.sidebar{
  grid-row: 2; grid-column: 1;
  overflow-y: auto;
  background: #fff;
  border-right: 1px solid var(--border);
  padding: 14px 0;
}
.sidebar .section{padding: 8px 14px 4px;}
.sidebar .section h3{
  font-size: 10.5px; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); margin-bottom: 6px; font-weight: 700;
}
.sidebar ul{list-style:none;}
.sidebar li{margin:1px 0;}
.sidebar a{
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 7px 10px; border-radius: 6px; font-size: 13px;
  color: var(--text); transition: background .12s;
}
.sidebar a:hover{background: var(--slate-50);}
.sidebar li.active > a{
  background: rgba(25,113,194,.12); color: var(--brand-d); font-weight: 600;
  box-shadow: inset 3px 0 0 var(--brand);
}
.sidebar .count{
  font-size: 11px; color: var(--muted); background: var(--slate-50);
  padding: 1px 8px; border-radius: 99px; font-variant-numeric: tabular-nums;
}
.sidebar .empty-note{font-size: 12px; color: var(--muted); font-style: italic; padding: 4px 10px;}

.main{
  grid-row: 2; grid-column: 2;
  overflow: hidden;
  display: grid;
  grid-template-rows: var(--kpi-h) 1fr;
  min-width: 0;
}
.kpi{
  grid-row: 1;
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
  padding: 20px 28px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}
.kpi-card{
  display: flex; flex-direction: column; justify-content: center;
  padding: 14px 18px; border: 1px solid var(--border); border-radius: 10px;
  background: var(--surface);
}
.kpi-card .lbl{font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 4px;}
.kpi-card .val{font-size: 26px; font-weight: 700; color: var(--text); font-variant-numeric: tabular-nums;}
.kpi-card.alt{border-color: var(--brand); background: rgba(25,113,194,.04);}

/* ===== Content — tek scrollable, contain:strict CLS izolasyonu ===== */
.content{
  grid-row: 2;
  overflow: auto;
  contain: strict;   /* layout + paint + size isolation */
  padding: 24px 28px;
  background: var(--bg);
  scrollbar-gutter: stable;
  transition: opacity .12s ease-out;
}
.content.loading{opacity: .55;}

.card-head{
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; flex-wrap: wrap;
  padding: 0 0 18px 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 18px;
}
.card-head h2{font-size: 18px; font-weight: 700; letter-spacing: -.01em;
  display: flex; align-items: center; gap: 10px;}
.kind-tag{
  font-size: 10.5px; font-weight: 600; padding: 3px 9px; border-radius: 99px;
  text-transform: uppercase; letter-spacing: .04em;
}
.kind-system,.kind-manual{background:#e7f1fa;color:var(--brand-d);}
.kind-external{background:#fff4e0;color:#8a4500;}
.kind-dynamic{background:#f3e7fa;color:#5b2a8a;}

.card-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.btn{
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 14px; font-size: 13px; font-weight: 500;
  background: #fff; border: 1px solid var(--border); border-radius: 7px;
  color: var(--text); cursor: pointer; transition: all .12s;
}
.btn:hover{border-color: var(--brand); color: var(--brand);}
.btn-primary{background: var(--brand); color: #fff; border-color: var(--brand);}
.btn-primary:hover{background: var(--brand-d); border-color: var(--brand-d); color: #fff;}
.search-form input{
  padding: 7px 12px; font-size: 13px; border: 1px solid var(--border); border-radius: 7px;
  width: 220px; background: #fff;
}
.search-form input:focus{outline:none; border-color: var(--brand);}

.toast{
  background: #d3f9d8; border: 1px solid #2f9e44; color: #14532d;
  padding: 10px 36px 10px 14px; border-radius: 7px;
  margin-bottom: 16px; position: relative;
  font-size: 13px;
}
.toast .toast-x{
  position: absolute; right: 8px; top: 6px; font-size: 18px; line-height: 1;
  color: #14532d; padding: 4px 8px; border-radius: 4px;
}
.toast .toast-x:hover{background: rgba(0,0,0,.06);}

.add-form{margin-bottom: 16px;}
.add-form details{
  border: 1px solid var(--border); border-radius: 8px; background: var(--surface);
}
.add-form summary{
  padding: 10px 14px; cursor: pointer; font-size: 13px; font-weight: 500;
  color: var(--brand-d); user-select: none;
}
.add-form summary:hover{background: var(--slate-50);}
.add-form-body{
  padding: 12px 14px 14px; border-top: 1px solid var(--border);
  display: grid; grid-template-columns: 1fr; gap: 8px;
}
.add-form-body textarea{
  width: 100%; padding: 8px 10px; font-family: 'SF Mono',monospace; font-size: 12.5px;
  border: 1px solid var(--border); border-radius: 6px; resize: vertical;
}
.add-form-body input[type=text]{
  padding: 7px 10px; font-size: 13px; border: 1px solid var(--border); border-radius: 6px;
}
.add-form-body .add-help{font-size: 11.5px; color: var(--muted); padding-top: 2px;}

table.data-table{
  width: 100%; border-collapse: collapse; table-layout: fixed;
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  overflow: hidden;
}
.data-table thead{background: var(--slate-50);}
.data-table th, .data-table td{
  padding: 9px 12px; font-size: 12.5px; text-align: left;
  border-bottom: 1px solid var(--border);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.data-table th{font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: 10.5px; letter-spacing: .05em;}
.data-table tbody tr{height: 38px;}
.data-table tbody tr:hover{background: var(--slate-50);}
.data-table tbody tr:last-child td{border-bottom: none;}
.empty-row td{text-align: center; color: var(--muted); padding: 32px 12px; font-style: italic;}

.tlp{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.02em;}
.tlp-white{background:#f1f5f9;color:#475569;border:1px solid #cbd5e1;}
.tlp-green{background:#dcfce7;color:#14532d;}
.tlp-amber{background:#fef3c7;color:#92400e;}
.tlp-red{background:#fee2e2;color:#991b1b;}

.pager{display:flex;align-items:center;justify-content:center;gap:14px;margin-top:18px;font-size:13px;}
.pager a{padding:6px 12px;border:1px solid var(--border);border-radius:6px;background:#fff;}
.pager a:hover{border-color:var(--brand);color:var(--brand);}
.pager .pager-info{color:var(--muted);}

.external-summary{padding-top:8px;}
.external-summary h3{font-size:13px;font-weight:600;color:var(--muted);margin-bottom:10px;}
.ext-list{list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;}
.ext-list li{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:12px 14px;display:flex;align-items:center;justify-content:space-between;
}
.ext-list a{font-weight:600;color:var(--brand-d);}
.ext-list a:hover{text-decoration:underline;}
.ext-count{font-size:12px;color:var(--muted);}
.ext-empty{color:var(--muted);font-style:italic;}

/* Accessibility */
:focus-visible{outline:2px solid var(--brand);outline-offset:2px;border-radius:4px;}
@media (prefers-reduced-motion: reduce){
  .content,.btn{transition:none;}
}
.skip-link{
  position:absolute;left:-9999px;top:auto;
}
.skip-link:focus{
  left:0;top:0;padding:8px 14px;background:#000;color:#fff;z-index:100;border-radius:0 0 6px 0;
}
</style>
</head>
<body>
<a class="skip-link" href="#content">İçeriğe atla</a>

<div class="app">
  <header class="topbar" role="banner">
    <div class="brand">
      <div class="brand-logo">CW</div>
      <span>Cyberwebeyeos Blacklist</span>
    </div>
    <div class="topbar-right">
      <span class="v2-tag">v2 BETA</span>
      <span><?= htmlspecialchars(cwe_current_user()) ?> · <?= htmlspecialchars(cwe_current_role()) ?></span>
      <a href="cyberwebeyeosblacklistadmin.php">v1'e dön</a>
    </div>
  </header>

  <nav class="sidebar" aria-label="Liste seçimi">
    <div class="section">
      <h3>Manuel Listeler</h3>
      <ul>
        <li class="<?= ($list_filter === 'all' || $list_filter === 'manual' || $list_filter === 'Manuel') ? 'active' : '' ?>">
          <a href="?list=all" data-list="all">
            <span>Tümü Manuel</span>
            <span class="count"><?= number_format($kpi_manuel, 0, ',', '.') ?></span>
          </a>
        </li>
        <?php foreach ($groups['system'] as $l): if (($l['slug'] ?? '') === 'manual') continue; ?>
          <li class="<?= ($list_filter === ($l['slug'] ?? '')) ? 'active' : '' ?>">
            <a href="?list=<?= urlencode($l['slug'] ?? '') ?>" data-list="<?= htmlspecialchars($l['slug'] ?? '') ?>">
              <span><?= htmlspecialchars($l['name'] ?? '') ?></span>
              <span class="count"><?= number_format(v2_count($l['file'] ?? ''), 0, ',', '.') ?></span>
            </a>
          </li>
        <?php endforeach; ?>
        <?php foreach ($groups['manual'] as $l): ?>
          <li class="<?= ($list_filter === ($l['slug'] ?? '')) ? 'active' : '' ?>">
            <a href="?list=<?= urlencode($l['slug'] ?? '') ?>" data-list="<?= htmlspecialchars($l['slug'] ?? '') ?>">
              <span><?= htmlspecialchars($l['name'] ?? '') ?></span>
              <span class="count"><?= number_format(v2_count($l['file'] ?? ''), 0, ',', '.') ?></span>
            </a>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>

    <div class="section">
      <h3>Dış Kaynaklar</h3>
      <ul>
        <li class="<?= ($list_filter === 'all-external') ? 'active' : '' ?>">
          <a href="?list=all-external" data-list="all-external">
            <span>Tümü Dış</span>
            <span class="count"><?= count($groups['external']) ?> kaynak</span>
          </a>
        </li>
        <?php foreach ($groups['external'] as $l): ?>
          <li class="<?= ($list_filter === ($l['slug'] ?? '')) ? 'active' : '' ?>">
            <a href="?list=<?= urlencode($l['slug'] ?? '') ?>" data-list="<?= htmlspecialchars($l['slug'] ?? '') ?>">
              <span><?= htmlspecialchars($l['name'] ?? '') ?></span>
              <span class="count"><?= number_format(v2_count($l['file'] ?? ''), 0, ',', '.') ?></span>
            </a>
          </li>
        <?php endforeach; ?>
        <?php if (empty($groups['external'])): ?>
          <li class="empty-note">Henüz dış kaynak yok</li>
        <?php endif; ?>
      </ul>
    </div>

    <div class="section">
      <h3>Akıllı Listeler</h3>
      <ul>
        <?php if (empty($groups['dynamic'])): ?>
          <li class="empty-note">Yakında — Sprint 9</li>
        <?php else: foreach ($groups['dynamic'] as $l): ?>
          <li class="<?= ($list_filter === ($l['slug'] ?? '')) ? 'active' : '' ?>">
            <a href="?list=<?= urlencode($l['slug'] ?? '') ?>" data-list="<?= htmlspecialchars($l['slug'] ?? '') ?>">
              <span><?= htmlspecialchars($l['name'] ?? '') ?></span>
              <span class="count"><?= number_format(v2_count($l['file'] ?? ''), 0, ',', '.') ?></span>
            </a>
          </li>
        <?php endforeach; endif; ?>
      </ul>
    </div>
  </nav>

  <main class="main">
    <section class="kpi" aria-label="Özet sayılar">
      <div class="kpi-card alt">
        <span class="lbl">Toplam Engellenen</span>
        <span class="val tabular"><?= number_format($kpi_total, 0, ',', '.') ?></span>
      </div>
      <div class="kpi-card">
        <span class="lbl">Manuel Kayıt</span>
        <span class="val tabular"><?= number_format($kpi_manuel, 0, ',', '.') ?></span>
      </div>
      <div class="kpi-card">
        <span class="lbl">Dış Kaynak Toplamı</span>
        <span class="val tabular"><?= number_format($kpi_external, 0, ',', '.') ?></span>
      </div>
      <div class="kpi-card">
        <span class="lbl">Aktif Feed Sayısı</span>
        <span class="val tabular"><?= number_format($kpi_feeds, 0, ',', '.') ?></span>
      </div>
    </section>

    <article id="content" class="content" aria-live="polite" aria-busy="false">
      <?php v2_render_content($active, $entries, $page, $total_pages, $list_filter, $search, $groups); ?>
    </article>
  </main>
</div>

<script>
/* Vanilla fetch swap — sadece .content innerHTML değişir, dış kabuk asla.
   html,body { overflow: hidden } + .content { overflow: auto, contain: strict }
   garantili: layout shift kategorik imkansız. */
(function(){
  const content = document.getElementById('content');
  const sidebar = document.querySelector('.sidebar');
  if (!content || !sidebar) return;

  function setActive(slug) {
    sidebar.querySelectorAll('li.active').forEach(li => li.classList.remove('active'));
    const a = sidebar.querySelector('a[data-list="' + CSS.escape(slug) + '"]');
    if (a && a.parentElement) a.parentElement.classList.add('active');
  }

  async function swap(url, push) {
    content.classList.add('loading');
    content.setAttribute('aria-busy', 'true');
    try {
      const sep = url.includes('?') ? '&' : '?';
      const r = await fetch(url + sep + 'fragment=1', { credentials: 'same-origin' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      content.innerHTML = await r.text();
      if (push) history.pushState({url}, '', url);
      content.scrollTop = 0;
    } catch (e) {
      content.innerHTML = '<div class="toast" role="alert">Yükleme hatası: ' + e.message + '</div>';
    } finally {
      content.classList.remove('loading');
      content.setAttribute('aria-busy', 'false');
    }
  }

  // Sidebar tıklama
  sidebar.addEventListener('click', (ev) => {
    const a = ev.target.closest('a[data-list]');
    if (!a) return;
    ev.preventDefault();
    const slug = a.dataset.list;
    setActive(slug);
    swap(a.getAttribute('href'), true);
  });

  // Back/forward
  window.addEventListener('popstate', (ev) => {
    const url = (ev.state && ev.state.url) || location.pathname + location.search;
    const params = new URLSearchParams(location.search);
    const slug = params.get('list') || 'all';
    setActive(slug);
    swap(url, false);
  });
})();
</script>
</body>
</html>

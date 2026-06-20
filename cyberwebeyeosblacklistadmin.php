<?php
// Portal authentication kontrolü (session_start burada yapılıyor)
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_once __DIR__ . '/ioc_helpers.php';
require_once __DIR__ . '/lib_firewall_feed.php';

// R26 (T1.1 RBAC): admin.php tüm POST handler'ları write mutation — admin/operator gerekli.
// Viewer rolü sayfayı görebilir (GET); ama POST'lar 403 döner + audit log.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_role(['admin','operator']);
}

error_reporting(E_ALL);
ini_set('display_errors', 1);
// header('Content-Type: text/html; charset=utf-8'); // Removed - causes issues after auth check

// Eğer message tanımlı değilse, başlangıçta boş bir değer atayın
if (!isset($_SESSION['message'])) {
    $_SESSION['message'] = "";
}

require_once __DIR__ . '/vendor/autoload.php';

// Settings'i oku
$config_file = "/var/www/html/settings_config.json";
$settings = [];
if (file_exists($config_file)) {
    $settings = json_decode(file_get_contents($config_file), true);
}
$logo = isset($settings['logo']) && !empty($settings['logo']) ? $settings['logo'] : 'cyberwebeyeos.png';
$instance_name = isset($settings['instance_name']) ? $settings['instance_name'] . ' - Admin Panel' : 'Cyberwebeyeos Blacklist - Admin Panel';

// Dosya yolları
$file_path = "/var/www/html/blacklist.txt";               // Manuel güncelleme için

// C3: Resolve target_list → file_path BEFORE any POST handler uses $file_path
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['target_list'])) {
    $__target_list = $_POST['target_list'] ?? 'all';
    if ($__target_list !== 'all' && $__target_list !== 'Manuel' && $__target_list !== 'manual') {
        $__lj = json_decode(file_get_contents(__DIR__ . '/lists.json'), true)['lists'] ?? [];
        foreach ($__lj as $__l) {
            if (($__l['slug'] ?? '') === $__target_list || ($__l['id'] ?? '') === $__target_list) {
                if (($__l['kind'] ?? '') === 'external') {
                    $__target_list = 'all'; // defensive: never write to external feeds
                    break;
                }
                if (!empty($__l['file'])) {
                    $file_path = $__l['file'];
                }
                break;
            }
        }
    }
}

// Bildirimleri göster
function display_message() {
    if (isset($_SESSION['message']) && !empty($_SESSION['message'])) {
        echo "<div class='alert'>
                {$_SESSION['message']}
                <span class='close' onclick='this.parentElement.style.display=\"none\";'>&times;</span>
              </div>";
        unset($_SESSION['message']);
    }
}

// IP Doğrulama Fonksiyonu
function validate_ip($ip) {
    if (strpos($ip, '/') !== false) {
        list($subnet, $prefix) = explode('/', $ip);
        return (filter_var($subnet, FILTER_VALIDATE_IP) && is_numeric($prefix) && $prefix >= 0 && $prefix <= 32);
    }
    return filter_var($ip, FILTER_VALIDATE_IP) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
}

// Private IP adreslerini kontrol eden fonksiyon
function is_private_ip($ip) {
    // IPv4 özel adres aralıkları
    $private_ips = [
        '10.0.0.0' => '10.255.255.255',   // 10.0.0.0/8
        '172.16.0.0' => '172.31.255.255',   // 172.16.0.0/12
        '192.168.0.0' => '192.168.255.255'  // 192.168.0.0/16
    ];

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_long = ip2long($ip);
        // Özel IP aralıklarında kontrol
        foreach ($private_ips as $start => $end) {
            $start_long = ip2long($start);
            $end_long = ip2long($end);
            if ($ip_long >= $start_long && $ip_long <= $end_long) {
                return true; // IP özel aralıkta
            }
        }
    }
    return false; // IP özel aralıkta değil
}

// IP'yi CIDR formatında doğrulama
function validate_cidr($cidr) {
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d+$/', $cidr)) {
        list($ip, $prefix) = explode('/', $cidr);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            if (is_private_ip($ip)) {
                return false; // Özel IP adresi CIDR formatında eklenemez
            }
            return true;
        }
    }
    return false;
}

// FQDN Doğrulama Fonksiyonu
function validate_fqdn($fqdn) {
    if (substr($fqdn, -1) === '.') {
        return false;
    }
    return (filter_var($fqdn, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false);
}

// R28 (T1.2): cwe_detect_type() artık ioc_helpers.php'de canonical IoC type'larıyla
// (ip-src/cidr/ipv6/domain/url/file-md5/file-sha1/file-sha256/email-src) tanımlı.

// FQDN var mı kontrolü
function fqdn_exists($fqdn) {
    global $file_path;
    $file_content = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($file_content as $item) {
        list(, , , $existing_fqdn) = explode("|", $item);
        if ($existing_fqdn == $fqdn) {
            return true;
        }
    }
    return false;
}

// IP var mı kontrolü
function ip_exists($ip) {
    global $file_path;
    $file_content = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($file_content as $item) {
        list($existing_ip) = explode("|", $item);
        if (strpos($existing_ip, '/') !== false) {
            if (is_ip_in_subnet_range($ip, $existing_ip)) {
                return $existing_ip;
            }
        } else {
            if ($existing_ip == $ip) {
                return $existing_ip;
            }
        }
    }
    return false;
}

// Subnet var mı kontrolü
function subnet_exists($ip) {
    global $file_path;
    $file_content = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($file_content as $item) {
        list($existing_ip) = explode("|", $item);
        if (strpos($existing_ip, '/') !== false && $existing_ip == $ip) {
            return true;
        }
    }
    return false;
}

// CIDR'den IP aralığını elde eden fonksiyon
function get_ip_range_from_cidr($cidr) {
    // Tek IP'lere /32 ekle (whitelist plain IP'ler için)
    if (strpos($cidr, '/') === false) $cidr .= '/32';
    $parts = explode('/', $cidr);
    $ip   = $parts[0];
    $mask = isset($parts[1]) ? (int)$parts[1] : 32;
    $ip_long = ip2long($ip);
    $mask_long = -1 << (32 - $mask);
    $network_start = $ip_long & $mask_long;
    $network_end = $network_start | (~$mask_long & 0xFFFFFFFF);
    return [long2ip($network_start), long2ip($network_end)];
}

// IP'nin CIDR bloğu içinde olup olmadığını kontrol etme
function is_ip_in_subnet_range($ip, $subnet) {
    list($start_ip, $end_ip) = get_ip_range_from_cidr($subnet);
    $ip_long = ip2long($ip);
    $start_long = ip2long($start_ip);
    $end_long = ip2long($end_ip);
    if ($ip_long === false || $start_long === false || $end_long === false) {
        return false;
    }
    return ($ip_long >= $start_long && $ip_long <= $end_long);
}
// cyberwebeyeos IP bloklarını ve whitelist'teki IP'leri kontrol eden fonksiyon
function is_cyberwebeyeos_ip($ip) {
    global $settings;

    // Config'den cyberwebeyeos bloklarını al, yoksa boş array kullan
    $cyberwebeyeos_blocks = isset($settings['cyberwebeyeos_blocks']) ? $settings['cyberwebeyeos_blocks'] : [];
    
    // Whitelist dosyasını oku ve bloklara ekle
    $whitelist_path = "/var/www/html/whitelist.txt";
    if (file_exists($whitelist_path)) {
        $whitelist_content = file($whitelist_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($whitelist_content as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            // Pipe-separated format: "IP|date|user|comment" — ilk alan = IP
            $entry = trim(explode('|', $line)[0]);
            if (empty($entry)) continue;
            $ipPart = explode('/', $entry)[0];
            if (filter_var($ipPart, FILTER_VALIDATE_IP) ||
                (strpos($entry, '/') !== false && validate_cidr($entry))) {
                $cyberwebeyeos_blocks[] = $entry;
            }
        }
    }
    
    if (strpos($ip, '/') === false) {
        $ip = $ip . '/32';
    }
    
    foreach ($cyberwebeyeos_blocks as $block) {
        if (is_ip_in_subnet_range(explode('/', $ip)[0], $block)) {
            return true;
        }
    }
    return false;
}

// Güncellenmiş Blacklist Görüntüleme Fonksiyonu (Optimize edildi)
function display_blacklist($search_ip = '', $per_page = 10, $page = 1, $list_filter = 'all') {
    global $file_path;

    // SPRINT7-AUDIT-B: all-external summary view — do NOT load data rows
    if ($list_filter === 'all-external') {
        $__ext_lists_json = __DIR__ . '/lists.json';
        $__ext_all = file_exists($__ext_lists_json)
            ? (json_decode(file_get_contents($__ext_lists_json), true)['lists'] ?? [])
            : [];
        $__ext_feeds = array_filter($__ext_all, fn($l) => ($l['kind'] ?? '') === 'external' && ($l['side'] ?? 'blacklist') === 'blacklist');
        echo "<div style='padding:12px 0;'>";
        echo "<p style='color:var(--text-muted);font-size:13px;margin:0 0 14px;'>Dış kaynak özetleri — detay için soldaki listeden kaynağa tıklayın.</p>";
        echo "<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;'>";
        foreach ($__ext_feeds as $__ef) {
            $__ef_name = htmlspecialchars($__ef['name'] ?? '');
            $__ef_slug = htmlspecialchars($__ef['slug'] ?? $__ef['id'] ?? '');
            $__ef_file = $__ef['file'] ?? '';
            $__ef_cnt = 0;
            $__ef_mtime = '—';
            if ($__ef_file && file_exists($__ef_file)) {
                $__fh_c = @fopen($__ef_file, 'r');
                if ($__fh_c) {
                    while (($__cl = fgets($__fh_c)) !== false) {
                        $__cl = trim($__cl);
                        if ($__cl !== '' && $__cl[0] !== '#') $__ef_cnt++;
                    }
                    fclose($__fh_c);
                }
                $__ef_mtime = date('d.m.Y H:i', filemtime($__ef_file));
            }
            $__ef_enabled = !empty($__ef['enabled']);
            $__ef_status_label = $__ef_enabled ? 'Aktif' : 'Pasif';
            $__ef_status_color = $__ef_enabled ? '#10b981' : '#94a3b8';
            echo "<div style='background:#fff;border:1px solid var(--border);border-radius:10px;padding:14px 16px;'>";
            echo "<div style='display:flex;align-items:center;gap:8px;margin-bottom:8px;'>";
            echo "<span style='font-size:16px;'>🌐</span>";
            echo "<strong style='font-size:13.5px;color:var(--text);'>{$__ef_name}</strong>";
            echo "<span style='margin-left:auto;font-size:11px;font-weight:600;color:{$__ef_status_color};'>{$__ef_status_label}</span>";
            echo "</div>";
            echo "<div style='font-size:28px;font-weight:700;color:var(--brand-500);line-height:1;margin-bottom:4px;'>" . number_format($__ef_cnt, 0, ',', '.') . "</div>";
            echo "<div style='font-size:11px;color:var(--text-muted);margin-bottom:10px;'>kayıt &nbsp;·&nbsp; Son güncelleme: {$__ef_mtime}</div>";
            echo "<a href='?list={$__ef_slug}' class='btn btn-ghost btn-sm' style='font-size:12px;'><i class='fas fa-eye'></i> Görüntüle</a>&nbsp;";
            echo "<button class='btn btn-ghost btn-sm ln-fetch' data-slug='{$__ef_slug}' style='font-size:12px;'><i class='fas fa-sync'></i> Şimdi Çek</button>";
            echo "</div>";
        }
        echo "</div></div>";
        return;
    }

    // SPRINT7-T8: Resolve list slug to file path via lists.json
    $__sprint7_list_file = null;
    $__sprint7_list_name = null;
    $__sprint7_list_kind = null;
    if ($list_filter !== 'all' && $list_filter !== 'Manuel') {
        $__sprint7_lists_json = __DIR__ . '/lists.json';
        if (file_exists($__sprint7_lists_json)) {
            $__sprint7_all = json_decode(file_get_contents($__sprint7_lists_json), true)['lists'] ?? [];
            foreach ($__sprint7_all as $__l) {
                if (($__l['slug'] ?? '') === $list_filter || ($__l['id'] ?? '') === $list_filter) {
                    $__sprint7_list_file = $__l['file'] ?? null;
                    $__sprint7_list_name = $__l['name'] ?? $list_filter;
                    $__sprint7_list_kind = $__l['kind'] ?? 'manual';
                    break;
                }
            }
        }
    }

    // Manuel güncellenebilen liste - sadece gerektiğinde oku
    $manual_items = [];
    if ($list_filter === 'all' || $list_filter === 'Manuel') {
        if (file_exists($file_path)) {
            $raw = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($raw as $line) {
                $trim = ltrim($line);
                if ($trim === '' || $trim[0] === '#') continue;
                $manual_items[] = $line;
            }
        }
    }

    // Listeyi oluştur
    $combined_items = [];
    foreach ($manual_items as $item) {
        $combined_items[] = ['data' => $item, 'editable' => true, 'source' => 'Manuel'];
    }
    
    // Liste filtreleme
    if ($list_filter !== 'all') {
        $filtered_by_source = [];
        foreach ($combined_items as $item) {
            if ($item['source'] === $list_filter) {
                $filtered_by_source[] = $item;
            }
        }
        $combined_items = $filtered_by_source;
    }

    // SPRINT7-T8-PERF: stream-paginated read instead of loading entire file
    if ($__sprint7_list_file && file_exists($__sprint7_list_file)) {
        $__sprint7_items = [];
        $__sprint7_per_page = $per_page > 0 ? $per_page : 50;
        $__sprint7_offset = ($page - 1) * $__sprint7_per_page;
        // R91b: dinamik (external/dynamic) liste search — line-wide stripos
        // case-insensitive; IP+yorum+domain+ticket+tip tek seferde yakalar.
        $__sprint7_search = (string)$search_ip;

        // First pass: count total non-empty data lines (fast — single pass, no parsing)
        // R91b: search aktifse sadece eşleşen satırları say (sonuç pagination doğru olsun).
        $__sprint7_total_lines = 0;
        $__sprint7_fh_count = @fopen($__sprint7_list_file, 'r');
        if ($__sprint7_fh_count) {
            while (($__l = fgets($__sprint7_fh_count)) !== false) {
                $__l = trim($__l);
                if ($__l === '' || $__l[0] === '#') continue;
                if ($__sprint7_search !== '' && stripos($__l, $__sprint7_search) === false) continue;
                $__sprint7_total_lines++;
            }
            fclose($__sprint7_fh_count);
        }

        // Second pass: read only the page slice (search aktifse sadece match'leri)
        $__sprint7_fh = @fopen($__sprint7_list_file, 'r');
        if ($__sprint7_fh) {
            $__sprint7_idx = 0;
            while (($__line = fgets($__sprint7_fh)) !== false) {
                $__line = trim($__line);
                if ($__line === '' || $__line[0] === '#') continue;
                // R91b: search filter — sadece line-wide match'lerle pagination yap.
                if ($__sprint7_search !== '' && stripos($__line, $__sprint7_search) === false) continue;
                if ($__sprint7_idx < $__sprint7_offset) { $__sprint7_idx++; continue; }
                if (count($__sprint7_items) >= $__sprint7_per_page) break;

                $__parts = explode('|', $__line);
                if (count($__parts) >= 10) {
                    $__sprint7_items[] = [
                        'ip' => $__parts[0], 'type' => $__parts[1] ?? '', 'comment' => $__parts[2] ?? '',
                        'date' => $__parts[3] ?? '', 'added_by' => $__parts[4] ?? '', 'fqdn' => $__parts[5] ?? '',
                        'jira' => $__parts[6] ?? '', 'tlp' => $__parts[7] ?? 'WHITE',
                        'confidence' => $__parts[8] ?? '50', 'valid_until' => $__parts[9] ?? 'permanent',
                        'source' => $__sprint7_list_name,
                        // Legacy key for table renderer
                        'data' => $__line,
                        'editable' => ($__sprint7_list_kind === 'system' || $__sprint7_list_kind === 'manual'),
                    ];
                } else {
                    $__sprint7_items[] = [
                        'ip' => trim($__parts[0]), 'type' => '', 'comment' => '', 'date' => '',
                        'added_by' => '', 'fqdn' => '', 'jira' => '', 'tlp' => 'WHITE',
                        'confidence' => 60, 'valid_until' => 'permanent',
                        'source' => $__sprint7_list_name,
                        'data' => trim($__parts[0]),
                        'editable' => false,
                    ];
                }
                $__sprint7_idx++;
            }
            fclose($__sprint7_fh);
        }

        // Override pagination: items are ALREADY the correct page slice
        $combined_items = $__sprint7_items;
        $filtered_items = $__sprint7_items;
        $total_items = $__sprint7_total_lines;
        $total_pages = max(1, ceil($total_items / $__sprint7_per_page));
        $page = max(1, min($page, $total_pages));
        $displayed_items = $__sprint7_items;
    }

    // Arama yapılıyorsa filtrele
if ($search_ip) {
    $filtered_items = [];
    $search_ip_only = $search_ip;
    
    // Eğer arama terimi CIDR formatındaysa, sadece IP kısmını çıkar
    if (strpos($search_ip, '/') !== false) {
        $search_ip_only = explode('/', $search_ip)[0];
    }
    
    foreach ($combined_items as $item) {
        // R91 Fix #3: Multi-field arama — pipe-separated satırın TÜM field'larını
        // (value/type/comment/date/added_by/fqdn/jira/tlp/conf/valid_until) kapsar.
        // stripos = case-insensitive; line-wide match IP+yorum+domain+ticket+tip
        // hepsini tek seferde yakalar.
        if (stripos($item['data'], $search_ip) !== false) {
            $filtered_items[] = $item;
            continue; // Eşleşme varsa diğer kontrolleri atla
        }
        
        // Arama teriminin subnet kontrolü için geçerli bir IP olup olmadığını kontrol et
        if (filter_var($search_ip_only, FILTER_VALIDATE_IP)) {
            // Öğe verisinden IP/subnet çıkar
            $item_ip = '';
            if ($item['source'] === 'Manuel') {
                // Manuel liste girişleri için IP, borudan önceki ilk kısımdır
                $entry_parts = explode("|", $item['data']);
                if (!empty($entry_parts[0])) {
                    $item_ip = $entry_parts[0];
                }
            } else {
                // Global listeler için, veri doğrudan IP/subnet'tir
                $item_ip = $item['data'];
            }
            
            // Eğer öğe bir subnet içeriyorsa ('/'), IP'nin o subnet içinde olup olmadığını kontrol et
            if (!empty($item_ip) && strpos($item_ip, '/') !== false) {
                if (is_ip_in_subnet_range($search_ip_only, $item_ip)) {
                    $filtered_items[] = $item;
                }
            }
        }
    }
} else {
    $filtered_items = $combined_items;
}
    
    // SPRINT7-T8-PERF: skip re-pagination if stream reader already did it
    if (!isset($displayed_items)) {
        $total_items = count($filtered_items);
        $total_pages = ceil($total_items / $per_page);
        if ($total_pages < 1) $total_pages = 1;
        $page = max(1, min($page, $total_pages));
        $start_index = ($page - 1) * $per_page;
        $displayed_items = array_slice($filtered_items, $start_index, $per_page);
    }
    // Liste filtre seçenekleri
    echo "<div class='search-bar'>";
    echo "<form method='get' action='" . htmlspecialchars($_SERVER["PHP_SELF"]) . "'>";
    echo "<table class='search-table' cellpadding='0' cellspacing='0'><tr>";
    echo "<td style='width:100%'><input type='text' name='search' class='form-control' placeholder='Ara (IP, yorum, domain, ticket, tip...)' value='" . htmlspecialchars($search_ip) . "'></td>";
    echo "<td><button type='submit' class='btn btn-primary'><i class='fas fa-search'></i> Ara</button></td>";
    echo "</tr></table>";
    echo "<input type='hidden' name='per_page' value='" . $per_page . "'>";
    echo "<input type='hidden' name='list_filter' value='" . $list_filter . "'>";
    echo "</form>";
    echo "</div>";
    if ($list_filter === 'all' || $list_filter === 'Manuel') {
        echo "<div class='action-bar'>";
        echo "<div class='filter-section'>";
        echo "<form method='get' action='" . htmlspecialchars($_SERVER["PHP_SELF"]) . "'>";
        echo "<label for='list_filter'>Liste Filtresi:</label>";
        echo "<select name='list_filter' id='list_filter' onchange='this.form.submit()'>";
        echo "<option value='all'" . ($list_filter === 'all' ? ' selected' : '') . ">Tüm Listeler</option>";
        echo "<option value='Manuel'" . ($list_filter === 'Manuel' ? ' selected' : '') . ">Manuel Liste</option>";
        echo "</select>";
        echo "<input type='hidden' name='search' value='" . htmlspecialchars($search_ip) . "'>";
        echo "<input type='hidden' name='per_page' value='" . $per_page . "'>";
        echo "<input type='hidden' name='page' value='1'>";
        echo "</form>";
        echo "</div>";

        echo "<div class='per-page-section'>";
        echo "<form method='get' action='" . htmlspecialchars($_SERVER["PHP_SELF"]) . "'>";
        echo "<label for='per_page'>Sayfa Başına:</label>";
        echo "<select name='per_page' id='per_page' onchange='this.form.submit()'>";
        $per_page_options = [10, 25, 50, 100];
        foreach ($per_page_options as $option) {
            echo "<option value='$option'" . ($option == $per_page ? ' selected' : '') . ">$option</option>";
        }
        echo "</select>";
        echo "<input type='hidden' name='search' value='" . htmlspecialchars($search_ip) . "'>";
        echo "<input type='hidden' name='page' value='$page'>";
        echo "<input type='hidden' name='list_filter' value='$list_filter'>";
        echo "</form>";
        echo "</div>";
        echo "</div>"; // action-bar end
    }
    
    // R91 Fix #2: Filtreleme dropdown kaldırıldı (user feedback: "listelerde filtreleme kaldıralım").
    // Önceki R75 quick-filter (Tümü/Bu hafta/Süresi dolanlar/Yüksek öncelikli) tablonun
    // üzerinde gereksiz kullanıldığı için silindi. Sidebar 3-section list picker korunur.

    // SPRINT7-T8: Per-list toolbar (only shown when a specific list is selected)
    if ($__sprint7_list_file && $__sprint7_list_kind !== null) {
        $__sprint7_list_slug = htmlspecialchars($list_filter);
        $__sprint7_list_name_esc = htmlspecialchars($__sprint7_list_name ?? $list_filter);
        $__sprint7_file_esc = htmlspecialchars(str_replace('/var/www/html/', '/blacklist/cyberwebeyeos/', $__sprint7_list_file ?? ''));
        $__sprint7_count = count($filtered_items ?? $combined_items);
        $__sprint7_is_manual = ($__sprint7_list_kind === 'manual' || $__sprint7_list_kind === 'system');
        echo "<div class='sprint7-list-toolbar' style='display:flex;gap:8px;align-items:center;margin:0 0 10px;padding:8px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;'>";
        echo "<span style='font-weight:600;color:#0c4a6e;font-size:13px;'>&#128203; {$__sprint7_list_name_esc}</span>";
        echo "<span style='color:#64748b;font-size:11.5px;'>({$__sprint7_count} kayıt)</span>";
        echo "<span style='flex:1;'></span>";
        if ($__sprint7_is_manual) {
            echo "<a href='" . $__sprint7_file_esc . "' target='_blank' class='btn btn-ghost btn-sm' title='Liste dosyasını indir'><i class='fas fa-download'></i> İndir</a>";
        }
        echo "<a href='?list=all' class='btn btn-ghost btn-sm' title='Tüm listelere dön'>&#10005; Listeden Çık</a>";
        echo "</div>";
    }

    echo "<div class='table-responsive'>";
    // R29 (T1.4): form artık bulk_action.php'ye gider
    echo "<form method='post' action='bulk_action.php' id='bulk-form'>";
    echo "<input type='hidden' name='action' id='bulk-action-input' value='delete'>";
    echo "<input type='hidden' name='type' id='bulk-type-input' value=''>";
    echo "<input type='hidden' name='confidence' id='bulk-conf-input' value=''>";
    echo "<input type='hidden' name='return_to' value='cyberwebeyeosblacklistadmin.php?tab=blacklist'>";
    echo "<table class='data-table bl-data-table' id='bl-data-table'>";
    echo "<thead>";
    // R84 (UX Pass-2 §1): 7 always-visible columns (+ chevron + checkbox).
    // Detail columns (FQDN/Jira/Süre/Liste/Provenance) moved to expandable detail row.
    echo "<tr>
            <th class='col-chevron' style='width:24px;'></th>
            <th class='col-check' style='width:32px;'><input type='checkbox' id='select-all' onclick='toggleAllCheckboxes()'></th>
            <th class='col-deger'>Değer</th>
            <th class='col-tip'>Tip</th>
            <th class='col-yorum'>Yorum</th>
            <th class='col-guven'>Güven</th>
            <th class='col-tarih'>Tarih</th>
            <th class='col-islem'>İşlem</th>
          </tr>";
    echo "</thead>";
    echo "<tbody>";

    if (count($displayed_items) == 0) {
        echo "<tr><td colspan='8' class='no-records'>Kayıt bulunamadı</td></tr>";
    } else {
        // R28 (T1.3): Type/Confidence badge'leri ioc_helpers.php'den gelir
        foreach ($displayed_items as $item) {
            if (!empty($item['data'])) {
                // R28 (T1.2): 10-field parse via ioc_helpers
                $e = cwe_parse_blacklist_entry($item['data']);
                $ip = $e['value']; $comment = $e['comment']; $date = $e['date'];
                $fqdn = $e['fqdn']; $jira = $e['jira'];

                // R93: TLP UI kaldırıldı — storage'da slot korunuyor (backward compat)
                $tm = cwe_type_meta($e['type']);
                $type_badge = "<span title=\"{$e['type']}\" style=\"background:{$tm['color']}20;color:{$tm['color']};padding:2px 7px;border-radius:4px;font-size:10.5px;font-weight:700;\">{$tm['label']}</span>";

                $conf_c = cwe_confidence_color($e['confidence']);
                $conf_html = "<span title=\"Güven skoru\" style=\"display:inline-flex;align-items:center;gap:4px;font-family:'Fira Code',monospace;font-size:11.5px;color:{$conf_c};font-weight:700;\">"
                           . "<span style=\"width:6px;height:6px;border-radius:50%;background:{$conf_c};\"></span>{$e['confidence']}</span>";

                if ($e['valid_until'] === 'permanent') {
                    $exp_html = "<span style=\"color:#94a3b8;font-size:11px;\" title=\"Süresiz\">∞</span>";
                } else {
                    $days = max(0, (int)ceil((strtotime($e['valid_until']) - time()) / 86400));
                    $expired = cwe_is_expired($e);
                    if ($expired) {
                        $exp_html = "<span style=\"background:#dc2626;color:#fff;padding:1px 6px;border-radius:4px;font-size:10.5px;font-weight:700;\" title=\"{$e['valid_until']}\">EXPIRED</span>";
                    } elseif ($days <= 7) {
                        $exp_html = "<span style=\"color:#f59e0b;font-size:11px;font-weight:600;\" title=\"{$e['valid_until']}\">{$days}g</span>";
                    } else {
                        $exp_html = "<span style=\"color:#475569;font-size:11px;\" title=\"{$e['valid_until']}\">{$days}g</span>";
                    }
                }

                // R49 (T5.4): row data-attrs for client-side quick filter
                $__row_expired = (int)cwe_is_expired($e);
                $__row_fp = (int)($fp_state_cache['fp_state'][$ip]['fp_count'] ?? 0);
                $__row_sight = (int)(($sighting_cache['sightings'][$ip]['count'] ?? 0)
                                     ?: ($sighting_cache['sightings'][rtrim($ip,'/32')]['count'] ?? 0));
                $__row_attrs = sprintf(
                    "data-bl-row=\"1\" data-conf=\"%d\" data-expired=\"%d\" data-date=\"%s\" data-fp=\"%d\" data-sighting=\"%d\"",
                    (int)$e['confidence'],
                    $__row_expired,
                    htmlspecialchars(substr($e['date'], 0, 10), ENT_QUOTES),
                    $__row_fp,
                    $__row_sight
                );
                // R84 (UX Pass-2 §2): Expandable row. data-id = $ip (unique per row).
                $__row_id = htmlspecialchars($ip, ENT_QUOTES);
                echo "<tr class='bl-row' data-id=\"{$__row_id}\" {$__row_attrs}>";
                // Chevron toggle indicator
                echo "<td class='col-chevron bl-chevron' style='text-align:center;color:#94a3b8;cursor:pointer;user-select:none;'>▶</td>";
                if ($item['editable']) {
                    echo "<td class='col-check'><input type='checkbox' name='selected_ips[]' value='$ip' class='record-checkbox'></td>";
                } else {
                    echo "<td class='col-check center'>-</td>";
                }
                // R31 (T2.1): GeoIP enrich placeholder (sadece IP/CIDR için)
                $enrich_html = '';
                if (in_array($e['type'], ['ip-src','ip-dst','cidr','ipv6','domain','hostname'], true)) {
                    $enrich_html = "<div class='ioc-enrich' data-value='" . htmlspecialchars($ip, ENT_QUOTES) . "' style='font-size:10.5px;color:#94a3b8;margin-top:2px;'>…</div>";
                }
                // R84: Yorum kolonu truncate + title tooltip (spec §1 row 4)
                $__comment_esc = htmlspecialchars($comment);
                $__comment_cell = $comment !== ''
                    ? "<span class='bl-comment-trunc' title=\"{$__comment_esc}\">{$__comment_esc}</span>"
                    : "<span style='color:#cbd5e1;'>—</span>";
                echo "<td class='col-deger'><a href='#' onclick=\"event.preventDefault(); event.stopPropagation(); showIocHistory('" . htmlspecialchars($ip, ENT_QUOTES) . "');\" style='color:inherit;text-decoration:none;border-bottom:1px dashed #94a3b8;cursor:pointer;' title='Investigation timeline'>" . htmlspecialchars($ip) . "</a>" . $enrich_html . "</td>
                      <td class='col-tip'>" . $type_badge . "</td>
                      <td class='col-yorum'>" . $__comment_cell . "</td>
                      <td class='col-guven'>" . $conf_html . "</td>
                      <td class='col-tarih' style='font-size:11.5px;color:#64748b;white-space:nowrap;'>" . htmlspecialchars(substr($date, 0, 10)) . "</td>";
                if ($item['editable']) {
                    // R32 (T2.2): FP badge + report button
                    $fp_count_disp = 0;
                    static $fp_state_cache = null;
                    if ($fp_state_cache === null) {
                        $fp_state_cache = @json_decode(@file_get_contents(__DIR__ . '/fp_state.json'), true);
                        if (!is_array($fp_state_cache)) $fp_state_cache = ['fp_state'=>[]];
                    }
                    $fp_count_disp = (int)($fp_state_cache['fp_state'][$ip]['fp_count'] ?? 0);
                    $fp_badge = $fp_count_disp > 0
                        ? "<span style='display:inline-block;background:#dc2626;color:#fff;padding:1px 5px;border-radius:4px;font-size:10px;font-weight:700;margin-right:4px;' title='FP raporu sayısı'>FP·{$fp_count_disp}</span>"
                        : '';
                    // R42 (T4.2): Sighting badge
                    static $sighting_cache = null;
                    if ($sighting_cache === null) {
                        $sighting_cache = @json_decode(@file_get_contents(__DIR__ . '/sighting_state.json'), true);
                        if (!is_array($sighting_cache)) $sighting_cache = ['sightings'=>[]];
                    }
                    // Check both /32 variant and bare
                    $s_data = $sighting_cache['sightings'][$ip] ?? ($sighting_cache['sightings'][rtrim($ip, '/32')] ?? null);
                    if (!$s_data && str_ends_with($ip, '/32')) {
                        $s_data = $sighting_cache['sightings'][substr($ip, 0, -3)] ?? null;
                    }
                    $sighting_badge = '';
                    if ($s_data && ($s_data['count'] ?? 0) > 0) {
                        $cnt = (int)$s_data['count'];
                        $sources_str = htmlspecialchars(implode(', ', array_keys($s_data['sources'] ?? [])));
                        $title = "👁 Sighting: {$cnt} · sources: {$sources_str} · last: " . htmlspecialchars($s_data['last_seen'] ?? '?');
                        $sighting_badge = "<span style='display:inline-block;background:#0ea5e9;color:#fff;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;margin-right:4px;' title=\"{$title}\">👁 {$cnt}</span>";
                    }
                    $fp_badge = $sighting_badge . $fp_badge;
                    $ip_esc = htmlspecialchars($ip, ENT_QUOTES);
                    // R84: İşlem butonları event.stopPropagation() ile row click'i tetiklemez
                    echo "<td class='col-islem bl-actions' onclick='event.stopPropagation();' style='white-space:nowrap;'>{$fp_badge}<a href='edit.php?ip={$ip_esc}' class='btn btn-edit' style='font-size:11px;padding:3px 8px;' onclick='event.stopPropagation();'>Düzenle</a> "
                       . "<button type='button' onclick=\"event.stopPropagation(); reportFP('{$ip_esc}')\" class='btn' style='font-size:11px;padding:3px 8px;background:#fef3c7;color:#92400e;border:1px solid #fde68a;border-radius:5px;cursor:pointer;' title='False Positive raporla'>🚨</button> "
                       . "<button type='button' onclick=\"event.stopPropagation(); vtLookup('{$ip_esc}')\" class='btn' style='font-size:11px;padding:3px 8px;background:#ede9fe;color:#5b21b6;border:1px solid #ddd6fe;border-radius:5px;cursor:pointer;' title='VirusTotal lookup'>VT</button></td>";
                } else {
                    echo "<td class='col-islem center'>Okunabilir</td>";
                }
                echo "</tr>";

                // R84 (UX Pass-2 §2): Detail row — FQDN/Jira/Süre/Liste/Provenance
                $__fqdn_html = $fqdn !== '' ? '<strong>FQDN:</strong> ' . htmlspecialchars($fqdn) : '';
                $__jira_html = '';
                if ($jira !== '') {
                    $__jira_esc = htmlspecialchars($jira);
                    if (preg_match('#^https?://#i', $jira)) {
                        $__jira_html = '<strong>Jira:</strong> <a href="' . $__jira_esc . '" target="_blank" rel="noopener" onclick="event.stopPropagation();" style="color:var(--brand-700);">' . $__jira_esc . '</a>';
                    } else {
                        $__jira_html = '<strong>Jira:</strong> ' . $__jira_esc;
                    }
                }
                $__sure_html = '<strong>Süre:</strong> ' . $exp_html;
                $__liste_html = '<strong>Liste:</strong> ' . htmlspecialchars($item['source']);
                $__prov_html = '';
                if ($item['editable']) {
                    $__prov_html = '<button class="ioc-prov-btn" data-ip="' . htmlspecialchars($ip, ENT_QUOTES) . '" onclick="event.stopPropagation();" style="background:none;border:1px solid var(--slate-200);color:#0e7490;cursor:pointer;font-size:12px;padding:2px 8px;border-radius:4px;" title="Provenance">ⓘ Provenance</button>';
                }
                $__parts = array_filter([$__fqdn_html, $__jira_html, $__sure_html, $__liste_html, $__prov_html], fn($s) => $s !== '');
                echo "<tr class='bl-row-detail hidden' data-for=\"{$__row_id}\">"
                   . "<td colspan='8'>"
                   . "<div class='row-detail-inner'>"
                   . implode(' <span class="row-detail-sep">|</span> ', $__parts)
                   . "</div></td></tr>";
            }
        }
    }
    
    echo "</tbody>";
    echo "</table>";

    // R29 (T1.4): Sticky bulk toolbar — JS ile activate olur
    echo <<<'HTML'
<div id="bulk-toolbar" style="position:sticky;bottom:0;background:linear-gradient(180deg,#0f172a 0%,#1e293b 100%);color:#fff;border-radius:12px 12px 0 0;padding:12px 16px;margin-top:10px;display:none;box-shadow:0 -4px 20px rgba(0,0,0,.2);z-index:30;border:1px solid #16a085;">
  <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
    <div style="font-weight:700;font-size:14px;">
      <i class="fas fa-check-circle" style="color:#10b981;"></i>
      <span id="bulk-count">0</span> IoC seçildi
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-left:auto;">
      <button type="button" class="btn btn-sm" onclick="bulkRun('export_csv')" style="background:#16a085;color:#fff;padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;">
        <i class="fas fa-download"></i> CSV Export
      </button>
      <button type="button" class="btn btn-sm" onclick="bulkRun('set_type')" style="background:#0ea5e9;color:#fff;padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;">
        Tip Ata
      </button>
      <button type="button" class="btn btn-sm" onclick="bulkRun('set_confidence')" style="background:#8b5cf6;color:#fff;padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;">
        Güven Ata
      </button>
      <button type="button" class="btn btn-sm" onclick="bulkRun('move_whitelist')" style="background:#10b981;color:#fff;padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;">
        → Whitelist
      </button>
      <button type="button" class="btn btn-sm" onclick="bulkRun('delete')" style="background:#dc2626;color:#fff;padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700;">
        <i class="fas fa-trash"></i> Sil
      </button>
    </div>
  </div>
</div>
<script>
(function(){
  function updateBulkToolbar(){
    var cbs = document.querySelectorAll('.record-checkbox:checked');
    var n = cbs.length;
    var tb = document.getElementById('bulk-toolbar');
    document.getElementById('bulk-count').textContent = n;
    tb.style.display = n > 0 ? 'block' : 'none';
  }
  document.addEventListener('change', function(e){
    if (e.target && (e.target.classList.contains('record-checkbox') || e.target.id === 'select-all')) {
      updateBulkToolbar();
    }
  });
  window.bulkRun = function(action){
    var cbs = document.querySelectorAll('.record-checkbox:checked');
    if (cbs.length === 0) { alert('Önce IoC seçin.'); return; }
    var n = cbs.length;
    var actionLabels = {
      delete: 'silinecek',
      move_whitelist: "whitelist'e taşınacak",
      set_type: 'için tip atanacak',
      set_confidence: 'için güven skoru atanacak',
      export_csv: 'CSV olarak indirilecek'
    };
    if (action === 'delete') {
      if (!confirm('🗑️ ' + n + ' IoC silinecek. Bu işlem geri alınamaz. Onaylıyor musun?')) return;
    } else if (action === 'move_whitelist') {
      if (!confirm('→ ' + n + " IoC whitelist'e taşınacak. Onaylıyor musun?")) return;
    } else if (action === 'set_type') {
      var t = prompt(n + ' IoC için tip:\n(ip-src/ip-dst/cidr/ipv6/domain/hostname/url/file-md5/file-sha1/file-sha256/email-src)', 'ip-src');
      if (!t) return;
      t = t.toLowerCase().trim();
      var valid = ['ip-src','ip-dst','cidr','ipv6','domain','hostname','url','file-md5','file-sha1','file-sha256','email-src'];
      if (valid.indexOf(t) < 0) { alert('Geçersiz tip'); return; }
      document.getElementById('bulk-type-input').value = t;
    } else if (action === 'set_confidence') {
      var c = prompt(n + ' IoC için güven skoru (0-100):', '75');
      if (c === null) return;
      var ci = parseInt(c, 10);
      if (isNaN(ci) || ci < 0 || ci > 100) { alert('0-100 arası bir sayı gir'); return; }
      document.getElementById('bulk-conf-input').value = ci;
    }
    document.getElementById('bulk-action-input').value = action;
    document.getElementById('bulk-form').submit();
  };

  // R39 (T3.4): VirusTotal lookup — fetch + popup (simple)
  window.vtLookup = async function(value){
    try {
      var r = await fetch('/blacklist/cyberwebeyeos/enrichment.php?action=vt&value=' + encodeURIComponent(value),
        {credentials:'same-origin'});
      var d = await r.json();
      if (!d.ok && d.error) { alert('VT: ' + d.error); return; }
      if (!d.found) { alert('VT: bilinmiyor (' + value + ')'); return; }
      var pct = d.vt_score;
      var verdict = pct === 0 ? '✅ Temiz' : pct < 5 ? '🟢 Düşük' : pct < 20 ? '🟡 Şüpheli' : '🔴 Yüksek tehdit';
      alert(
        'VirusTotal: ' + value + '\\n\\n' +
        verdict + ' (skor: ' + pct + '/100)\\n\\n' +
        'Malicious:   ' + d.malicious + '/' + d.total_engines + '\\n' +
        'Suspicious:  ' + d.suspicious + '\\n' +
        'Harmless:    ' + d.harmless + '\\n' +
        'Undetected:  ' + d.undetected + '\\n' +
        'Reputation:  ' + (d.reputation || 0) + '\\n\\n' +
        'Son analiz:  ' + (d.last_analysis_date || '-') + '\\n' +
        'Kaynak:      ' + d.source
      );
    } catch(e) { alert('VT lookup hatası: ' + e.message); }
  };

  // R46 (T5.1): Investigation timeline drawer
  function _fmtBadge(label, color, title){
    return '<span title="' + (title||'') + '" style="display:inline-block;background:' + color + ';color:#fff;padding:2px 8px;border-radius:4px;font-size:10.5px;font-weight:700;letter-spacing:.04em;margin-right:4px;">' + label + '</span>';
  }
  function _section(title, html){
    if (!html) return '';
    return '<h3 style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin:18px 0 8px;">' + title + '</h3>' + html;
  }
  window.showIocHistory = async function(value){
    const drawer = document.getElementById('ioc-drawer');
    const bg = document.getElementById('ioc-drawer-bg');
    const content = document.getElementById('ioc-drawer-content');
    content.innerHTML = '<p style="color:#64748b;">Yükleniyor…</p>';
    bg.style.display = 'block'; drawer.style.display = 'block';
    try {
      const r = await fetch('/blacklist/cyberwebeyeos/ioc_history.php?value=' + encodeURIComponent(value), {credentials:'same-origin'});
      const d = await r.json();
      if (!d.ok) { content.innerHTML = '<p style="color:#dc2626;">Hata: ' + (d.error||'?') + '</p>'; return; }

      let html = '<h2 style="font-family:\'Fira Code\',monospace;font-size:17px;margin:0 0 4px;">' + value.replace(/</g,'&lt;') + '</h2>';
      html += '<p style="color:#64748b;font-size:12px;margin-bottom:14px;">Investigation timeline · ' + d.now + '</p>';

      // Current entry
      if (d.current_entry) {
        const e = d.current_entry;
        let badges = '';
        badges += _fmtBadge(e.tlp, e.tlp==='RED'?'#dc2626':e.tlp==='AMBER'?'#f59e0b':e.tlp==='GREEN'?'#10b981':'#94a3b8');
        badges += _fmtBadge(e.type, '#6366f1');
        badges += _fmtBadge('Conf ' + e.confidence, e.confidence>=80?'#10b981':e.confidence>=60?'#0ea5e9':e.confidence>=40?'#f59e0b':'#ef4444');
        if (e.is_expired) badges += _fmtBadge('EXPIRED', '#dc2626');
        const c = '<div style="background:#f8fafc;padding:12px;border-radius:8px;font-size:12px;">' + badges +
                  '<div style="margin-top:8px;color:#475569;">' + (e.comment||'(yorum yok)').replace(/</g,'&lt;') + '</div>' +
                  '<div style="margin-top:6px;font-size:11px;color:#64748b;">Eklendi: ' + e.date + ' · added_by: ' + e.added_by + ' · expires: ' + (e.valid_until||'permanent') + '</div></div>';
        html += _section('Mevcut Kayıt', c);
      } else {
        html += _section('Mevcut Kayıt', '<p style="color:#94a3b8;font-size:12px;">Blacklist\'te bulunamadı</p>');
      }

      // Sighting
      if (d.sighting) {
        const s = d.sighting;
        const srcs = Object.entries(s.sources||{}).map(([k,v]) => '<span style="background:#e0e7ff;color:#3730a3;padding:1px 6px;border-radius:3px;font-size:10.5px;margin-right:3px;">' + k + ':' + v + '</span>').join('');
        html += _section('👁 Sighting (SIEM match)',
          '<div style="background:#dbeafe;padding:10px;border-radius:8px;font-size:12px;">' +
          '<b>Toplam:</b> ' + s.count + ' match · <b>İlk:</b> ' + s.first_seen + ' · <b>Son:</b> ' + s.last_seen +
          '<div style="margin-top:8px;">Kaynaklar: ' + srcs + '</div></div>');
      }

      // FP
      if (d.fp) {
        const f = d.fp;
        let reports = (f.reports||[]).slice(-5).reverse().map(r => '<li style="font-size:11px;color:#475569;">' + r.ts + ' <code>' + r.user + '</code>: ' + (r.comment||'(no note)').replace(/</g,'&lt;') + '</li>').join('');
        html += _section('🚨 False Positive',
          '<div style="background:#fef2f2;padding:10px;border-radius:8px;font-size:12px;">' +
          '<b>FP raporu:</b> ' + f.fp_count + ' · <b>Son:</b> ' + f.last_fp_report +
          '<ul style="margin-top:8px;padding-left:18px;">' + reports + '</ul></div>');
      }

      // Enrichments
      if (d.enrichments && Object.keys(d.enrichments).length) {
        const e = d.enrichments;
        let p = '';
        if (e.geoip) {
          p += '<div style="background:#f0fdf4;padding:10px;border-radius:8px;font-size:12px;margin-bottom:6px;">' +
               '<b>🌍 GeoIP</b> · ' + (e.geoip.flag||'') + ' ' + (e.geoip.country||'?') + ' / ' + (e.geoip.city||'') +
               ' · AS' + (e.geoip.asn||'?') + ' ' + (e.geoip.org||'') +
               '<div style="font-size:10.5px;color:#64748b;margin-top:4px;">' + (e.geoip.source||'?') + ' · cached: ' + (e.geoip.cached_at||'?') + '</div></div>';
        }
        if (e.virustotal) {
          const v = e.virustotal;
          const scoreCol = (v.vt_score||0) === 0 ? '#10b981' : (v.vt_score < 5 ? '#0ea5e9' : v.vt_score < 20 ? '#f59e0b' : '#dc2626');
          p += '<div style="background:#fef9c3;padding:10px;border-radius:8px;font-size:12px;">' +
               '<b>🦠 VirusTotal</b> · <span style="background:' + scoreCol + ';color:#fff;padding:1px 7px;border-radius:3px;font-weight:700;">' + v.vt_score + '/100</span>' +
               ' · M:' + (v.malicious||0) + ' / S:' + (v.suspicious||0) + ' / H:' + (v.harmless||0) +
               '<div style="font-size:10.5px;color:#64748b;margin-top:4px;">Last: ' + (v.last_analysis_date||'?') + ' · cached: ' + (v.cached_at||'?') + '</div></div>';
        }
        html += _section('🔍 Enrichment Cache', p);
      }

      // Pending
      if (d.pending) {
        html += _section('⏳ Pending Approval',
          '<div style="background:#fef3c7;padding:10px;border-radius:8px;font-size:12px;">' +
          '<b>Status:</b> ' + d.pending.status + ' · <b>Source:</b> ' + d.pending.source +
          ' · <b>Reason:</b> ' + (d.pending.reason || '-').replace(/</g,'&lt;') + '</div>');
      }

      // Whitelist
      if (d.whitelist) {
        html += _section('✅ Whitelist',
          '<div style="background:#dcfce7;padding:10px;border-radius:8px;font-size:12px;">' +
          '<b>TLP:</b> ' + d.whitelist.tlp + ' · <b>By:</b> ' + d.whitelist.user + ' · <b>Date:</b> ' + d.whitelist.date +
          (d.whitelist.comment ? '<div style="margin-top:4px;">' + d.whitelist.comment.replace(/</g,'&lt;') + '</div>' : '') + '</div>');
      }

      // Warninglist / BigTech
      if (d.warninglist) {
        html += _section('⚠️ Warninglist Match',
          '<div style="background:#fef3c7;padding:10px;border-radius:8px;font-size:12px;">' +
          '<b>List:</b> ' + d.warninglist.list + ' · <b>Match:</b> ' + d.warninglist.value + ' (' + d.warninglist.rule + ') · ' + d.warninglist.label + '</div>');
      }
      if (d.bigtech) {
        html += _section('☁ Big Tech CIDR',
          '<div style="background:#e0e7ff;padding:10px;border-radius:8px;font-size:12px;">' +
          '<b>Provider:</b> ' + d.bigtech.provider + ' · <b>Service:</b> ' + d.bigtech.service + ' · <b>CIDR:</b> ' + d.bigtech.cidr + '</div>');
      }

      // Audit events timeline (kompakt liste)
      if (d.audit_events && d.audit_events.length) {
        const colorOf = (a) => a.startsWith('warninglist')?'#f59e0b':a.startsWith('fp')?'#dc2626':a.startsWith('cve')?'#5b21b6':a.startsWith('bigtech')?'#0ea5e9':a.startsWith('sighting')?'#3730a3':a.startsWith('bulk')?'#16a085':a.includes('add')?'#10b981':a.includes('delete')?'#dc2626':'#64748b';
        let rows = d.audit_events.map(e => {
          return '<tr><td style="padding:4px 6px;font-size:10.5px;color:#64748b;white-space:nowrap;">' + e.ts + '</td>' +
                 '<td style="padding:4px 6px;"><span style="background:' + colorOf(e.action) + ';color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;">' + e.action + '</span></td>' +
                 '<td style="padding:4px 6px;font-size:10.5px;color:#475569;">' + e.user + '</td>' +
                 '<td style="padding:4px 6px;font-size:10px;color:#64748b;font-family:\'Fira Code\',monospace;">' + JSON.stringify(e.details||{}).slice(0,80) + '</td></tr>';
        }).join('');
        html += _section('📋 Audit Timeline (' + d.audit_count + ')',
          '<table style="width:100%;font-size:11px;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;"><thead><tr style="background:#f8fafc;"><th style="padding:6px;text-align:left;font-size:10px;color:#64748b;">Zaman</th><th style="padding:6px;text-align:left;font-size:10px;color:#64748b;">Aksiyon</th><th style="padding:6px;text-align:left;font-size:10px;color:#64748b;">User</th><th style="padding:6px;text-align:left;font-size:10px;color:#64748b;">Details</th></tr></thead><tbody>' + rows + '</tbody></table>');
      }

      content.innerHTML = html;
    } catch(err) {
      content.innerHTML = '<p style="color:#dc2626;">Hata: ' + err.message + '</p>';
    }
  };
  window.closeIocHistory = function(){
    document.getElementById('ioc-drawer').style.display = 'none';
    document.getElementById('ioc-drawer-bg').style.display = 'none';
  };

  // R32 (T2.2): False Positive report — prompt for comment, submit hidden form
  window.reportFP = function(value){
    var comment = prompt('🚨 False Positive raporu: "' + value + '"\n\nNeden yanlış pozitif? (opsiyonel):', '');
    if (comment === null) return; // user cancelled
    var f = document.createElement('form');
    f.method = 'POST';
    f.action = 'fp_report.php';
    f.style.display = 'none';
    f.innerHTML = '<input name="value" value="' + encodeURIComponent(value).replace(/"/g, '&quot;') + '">' +
                  '<input name="comment">' +
                  '<input name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=blacklist">';
    f.querySelector('input[name="value"]').value = value;
    f.querySelector('input[name="comment"]').value = comment;
    document.body.appendChild(f);
    f.submit();
  };

  // R31 (T2.1): Lazy GeoIP enrichment — 40 req/min throttle (ip-api.com'un 45/min'inden güvenli)
  function enrichOne(cell){
    const v = cell.getAttribute('data-value');
    if (!v) return Promise.resolve();
    return fetch('/blacklist/cyberwebeyeos/enrichment.php?value=' + encodeURIComponent(v), {credentials:'same-origin'})
      .then(r => r.json())
      .then(d => {
        if (!d || !d.ok) { cell.textContent = ''; return; }
        const flag = d.flag || '';
        const cc = d.country_code || '';
        const asn = d.asn ? ('AS' + d.asn) : '';
        const org = (d.org || '').slice(0, 22);
        const parts = [];
        if (flag) parts.push(flag);
        if (cc) parts.push(cc);
        if (asn) parts.push(asn);
        if (org) parts.push(org);
        cell.textContent = parts.join(' · ');
        cell.title = 'Ülke: ' + (d.country || '?') + (d.city ? ' / ' + d.city : '') +
                     '\nAS' + (d.asn || '?') + ' ' + (d.org || '') +
                     '\nISP: ' + (d.isp || '?') +
                     '\nSource: ' + (d.source || '?');
      })
      .catch(e => { cell.textContent = ''; });
  }
  function enrichAll(){
    const cells = Array.from(document.querySelectorAll('.ioc-enrich'));
    // Sıralı + 1500ms throttle = ~40 req/min (ip-api.com 45/min limit altı).
    // Cache hit'leri server-side instant, throttle yine de uygulanır (basit, güvenli).
    let i = 0;
    function next(){
      if (i >= cells.length) return;
      enrichOne(cells[i]).finally(() => {
        i++;
        setTimeout(next, 1500);
      });
    }
    next();
  }
  // Sayfa yüklendikten 200ms sonra başlat (initial paint'i bloklamasın)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(enrichAll, 200));
  } else {
    setTimeout(enrichAll, 200);
  }
})();
</script>
HTML;
    echo "</form>";
    echo "</div>"; // table-responsive end
    
            echo "<div class='record-info'>Toplam: <b>$total_items</b> kayıt</div>";
    
    // Sayfalama (R89e: tüm mevcut query string preserve; fragment param drop)
    if ($total_pages > 1) {
        $__pg_base = $_GET;
        unset($__pg_base['fragment']); // fragment'i URL'e yazmayalim
        $__mk = function($n) use ($__pg_base) {
            return '?' . http_build_query(array_merge($__pg_base, ['page' => $n]));
        };
        echo "<div class='pagination'>";
        if ($page > 1) {
            echo "<a href='" . htmlspecialchars($__mk($page - 1)) . "' class='page-link' data-bl-page='" . ($page - 1) . "'>&laquo; Önceki</a>";
        }

        // Sayfa numaralarını göster
        $max_pages_to_show = 5;
        $start_page = max(1, min($page - floor($max_pages_to_show / 2), $total_pages - $max_pages_to_show + 1));
        $end_page = min($start_page + $max_pages_to_show - 1, $total_pages);

        if ($start_page > 1) {
            echo "<a href='" . htmlspecialchars($__mk(1)) . "' class='page-link' data-bl-page='1'>1</a>";
            if ($start_page > 2) {
                echo "<span class='page-ellipsis'>...</span>";
            }
        }

        for ($i = $start_page; $i <= $end_page; $i++) {
            if ($i == $page) {
                echo "<span class='page-link current'>$i</span>";
            } else {
                echo "<a href='" . htmlspecialchars($__mk($i)) . "' class='page-link' data-bl-page='$i'>$i</a>";
            }
        }

        if ($end_page < $total_pages) {
            if ($end_page < $total_pages - 1) {
                echo "<span class='page-ellipsis'>...</span>";
            }
            echo "<a href='" . htmlspecialchars($__mk($total_pages)) . "' class='page-link' data-bl-page='$total_pages'>$total_pages</a>";
        }

        if ($page < $total_pages) {
            echo "<a href='" . htmlspecialchars($__mk($page + 1)) . "' class='page-link' data-bl-page='" . ($page + 1) . "'>Sonraki &raquo;</a>";
        }
        echo "</div>";
    }
}

// IP'yi prefix formatına çevir
function convert_ip_to_prefix($ip) {
    if (strpos($ip, '/') !== false) {
        return $ip;
    }
    return "$ip/32"; 
}

// Manuel senkronizasyon (sadece buton tıklandığında çalışır)
// Whitelist add/delete (inline — kullanıcı admin sayfasında kalır)
if ($_SERVER["REQUEST_METHOD"] == "POST" && (isset($_POST['wl_add']) || isset($_POST['wl_delete']))) {
    $wl_file = '/var/www/html/whitelist.txt';
    $msgs = [];

    if (!empty($_POST['wl_add'])) {
        $entry = trim($_POST['wl_add']);
        // basit validasyon: IP veya CIDR
        $valid = false;
        if (strpos($entry, '/') !== false) {
            list($ip, $prefix) = explode('/', $entry, 2);
            $valid = filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($prefix) && $prefix >= 0 && $prefix <= 128;
        } else {
            $valid = filter_var($entry, FILTER_VALIDATE_IP) !== false;
        }
        if (!$valid) {
            $msgs[] = "❌ Geçersiz IP/CIDR: " . htmlspecialchars($entry);
        } else {
            $existing = file_exists($wl_file) ? file($wl_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            $existing_clean = array_map('trim', array_filter($existing, fn($l)=>trim($l)!=='' && trim($l)[0]!=='#'));
            // Yeni format: entry|date|user|comment (geriye dönük uyumlu: list parse'da $existing_clean tek değer olarak alıyor → bu yüzden iki kontrol)
            $exists = false;
            foreach ($existing_clean as $line) {
                $clean_entry = explode('|', $line)[0];
                if (trim($clean_entry) === $entry) { $exists = true; break; }
            }
            if ($exists) {
                $msgs[] = "ℹ️ Zaten whitelist'te: " . htmlspecialchars($entry);
            } else {
                $now = date('Y-m-d H:i:s');
                $user = $_SESSION['cwe_user'] ?? 'admin';
                $note = trim($_POST['wl_comment'] ?? '');
                $tlp = in_array(($_POST['wl_tlp'] ?? 'WHITE'), ['RED','AMBER','GREEN','WHITE'], true) ? $_POST['wl_tlp'] : 'WHITE';
                $line = $entry . '|' . $now . '|' . $user . '|' . str_replace('|', ' ', $note) . '|' . $tlp;
                file_put_contents($wl_file, $line . "\n", FILE_APPEND);
                audit_log_event('whitelist_add', ['entry'=>$entry, 'comment'=>$note, 'tlp'=>$tlp]);
                $msgs[] = "✓ Whitelist'e eklendi: " . htmlspecialchars($entry);
            }
        }
    }

    if (!empty($_POST['wl_delete'])) {
        $entry = trim($_POST['wl_delete']);
        if (file_exists($wl_file)) {
            $lines = file($wl_file, FILE_IGNORE_NEW_LINES);
            // Pipe-separated formatla uyumlu — ilk alan = IP/CIDR
            $new = array_filter($lines, fn($l) => trim(explode('|', $l)[0]) !== $entry);
            file_put_contents($wl_file, implode("\n", $new) . (count($new) ? "\n" : ''));
            audit_log_event('whitelist_delete', ['entry'=>$entry]);
            $msgs[] = "✓ Whitelist'ten silindi: " . htmlspecialchars($entry);
        }
    }

    $_SESSION['message'] = implode('<br>', $msgs);
    header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=whitelist');
    exit;
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['sync_blacklist'])) {
    $r = rebuild_firewall_feed();
    if ($r['ok']) {
        $_SESSION['message'] = "Firewall feed yeniden oluşturuldu: {$r['count']} giriş ({$r['subtracted']} whitelist çıkarıldı).";
    } else {
        $_SESSION['message'] = "Feed rebuild hatası: " . htmlspecialchars($r['error'] ?? 'bilinmeyen hata');
    }
}

// Manuel ekleme (POST ile)
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['ip_address'])) {
    $ip_input = isset($_POST['ip_address']) ? trim($_POST['ip_address']) : '';
    $comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
    $fqdn = isset($_POST['fqdn']) ? trim($_POST['fqdn']) : '';
    $jira = isset($_POST['jira']) ? trim($_POST['jira']) : '';

    if (empty($ip_input) && empty($fqdn)) {
        $_SESSION['message'] = "Lütfen en az bir IP adresi veya FQDN girin.";
    } elseif (!empty($ip_input) && !empty($fqdn)) {
        $_SESSION['message'] = "Sadece bir IP adresi veya FQDN girin, her ikisini birden girmeyin.";
    } else {
        if (!empty($ip_input)) {
            // Newline + virgül her ikisini de destekle
            $ip_addresses = preg_split('/[\r\n,]+/', $ip_input);
            $ip_addresses = array_filter(array_map('trim', $ip_addresses), function($s){
                return $s !== '' && $s[0] !== '#';
            });
            foreach ($ip_addresses as $ip_input) {
                $ip_input = trim($ip_input);
                // R81 (audit-C1): detect IoC type first; only apply IP logic for IP/CIDR types
                $force_type = trim($_POST['force_type'] ?? '');
                $ioc_type = $force_type !== '' ? $force_type : cwe_detect_type($ip_input);
                $is_ip_type = in_array($ioc_type, ['ip-src', 'ip-dst', 'ipv6', 'cidr'], true);

                if ($ioc_type === 'unknown') {
                    $_SESSION['message'] .= "Tanınmayan IoC formatı: " . htmlspecialchars($ip_input) . "<br>";
                    continue;
                }

                if ($is_ip_type) {
                    // IP/CIDR path — existing validation logic
                    if (strpos($ip_input, '/') === false) {
                        $ip_input .= '/32';
                    }
                    if (is_private_ip(explode('/', $ip_input)[0])) {
                        $_SESSION['message'] .= "Özel IP adresi (Private IP) eklenemez: " . cwe_msg_escape($ip_input) . "<br>";
                        continue;
                    }
                    if (!validate_ip($ip_input)) {
                        $_SESSION['message'] .= "Geçersiz IP adresi veya subnet prefix: " . cwe_msg_escape($ip_input) . "<br>";
                        continue;
                    }
                    if (is_cyberwebeyeos_ip($ip_input)) {
                        $_SESSION['message'] .= "Bu IP, cyberwebeyeos ve cyberwebeyeos ortamlarına aittir ve eklenemez: " . cwe_msg_escape($ip_input) . "<br>";
                        continue;
                    }
                    $existing_ip_or_subnet = ip_exists($ip_input);
                    if ($existing_ip_or_subnet) {
                        $_SESSION['message'] .= "Bu IP adresi veya subnet zaten mevcut: " . cwe_msg_escape($ip_input) . ", mevcut subnet: " . cwe_msg_escape($existing_ip_or_subnet) . "<br>";
                        continue;
                    }
                    list($ip, $cidr) = explode('/', $ip_input);
                    if (is_private_ip($ip)) {
                        $_SESSION['message'] .= "Özel IP adresi (Private IP) eklenemez: " . cwe_msg_escape($ip_input) . "<br>";
                        continue;
                    } elseif (!validate_ip($ip_input)) {
                        $_SESSION['message'] .= "Geçersiz IP adresi veya subnet prefix: " . cwe_msg_escape($ip_input) . "<br>";
                        continue;
                    }
                    $file_content = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    $skip = false;
                    foreach ($file_content as $item) {
                        list($existing_ip) = explode("|", $item);
                        if (strpos($existing_ip, '/') !== false) {
                            if (is_ip_in_subnet_range($ip, $existing_ip)) {
                                $_SESSION['message'] .= "Bu IP, mevcut subnet aralığındadır ve eklenemez: " . cwe_msg_escape($ip_input) . "<br>";
                                $skip = true;
                                break;
                            }
                        }
                    }
                    if ($skip) {
                        continue;
                    }
                }
                // Shared path: warninglist, bigtech, write entry (IP and non-IP types)
                $date = new DateTime('now', new DateTimeZone('Europe/Istanbul'));
                $date_string = $date->format('Y-m-d H:i:s');
                // R41 (T4.1): Warninglist guard — match varsa engelle, override ile geç
                $wl_match = cwe_warninglist_match($ip_input);
                $override = !empty($_POST['warninglist_override']);
                if ($wl_match && !$override) {
                    $_SESSION['message'] .= "🛑 <b>WARNINGLIST ENGEL:</b> " . cwe_msg_escape($ip_input) . " <code>" .
                        htmlspecialchars($wl_match['list']) . "</code> listesinde — " .
                        htmlspecialchars($wl_match['label']) . " (" . htmlspecialchars($wl_match['value']) . "). " .
                        "Eklenmedi. Gerçekten eklemek istiyorsan formdaki <b>Warninglist override</b> kutusunu işaretle.<br>";
                    audit_log_event('warninglist_block', ['entry'=>$ip_input, 'match'=>$wl_match]);
                    continue;
                } elseif ($wl_match && $override) {
                    $_SESSION['message'] .= "⚠️ <b>WARNINGLIST OVERRIDE:</b> " . cwe_msg_escape($ip_input) . " <code>" .
                        htmlspecialchars($wl_match['list']) . "</code> listesinde olmasına rağmen eklendi (operatör onayı).<br>";
                    audit_log_event('warninglist_override', ['entry'=>$ip_input, 'match'=>$wl_match]);
                }
                // R34 (T2.4): big tech overlap warning — only relevant for IPs
                if ($is_ip_type) {
                    $bigtech_match = cwe_bigtech_match($ip_input);
                    if ($bigtech_match) {
                        $_SESSION['message'] .= "⚠️ <b>UYARI:</b> " . cwe_msg_escape($ip_input) . " <b>" .
                            strtoupper($bigtech_match['provider']) . "</b> (" .
                            htmlspecialchars($bigtech_match['service']) . ") aralığıyla çakışıyor (" .
                            htmlspecialchars($bigtech_match['cidr']) . "). Kayıt yine de eklendi — gerekirse whitelist'e taşı veya kaldır.<br>";
                        audit_log_event('bigtech_overlap_warning', ['entry'=>$ip_input, 'match'=>$bigtech_match]);
                    }
                }
                // R28 (T1.2): 10-field schema — TLP, type, confidence, valid_until
                $tlp_in = strtoupper(trim($_POST['tlp'] ?? 'WHITE'));
                $conf_in = max(0, min(100, (int)($_POST['confidence'] ?? 75)));
                // R28 (T1.2): preset > custom date > default +90 days
                $preset = trim($_POST['valid_until_preset'] ?? '+90 days');
                $custom = trim($_POST['valid_until'] ?? '');
                if ($preset === 'permanent') {
                    $vu_in = 'permanent';
                } elseif ($preset === 'custom' && $custom !== '') {
                    $ts = strtotime($custom);
                    $vu_in = $ts ? date('Y-m-d H:i:s', $ts) : cwe_default_valid_until(90);
                } else {
                    // relative preset (+30/+90/+180/+365 days)
                    $ts = strtotime($preset);
                    $vu_in = $ts ? date('Y-m-d H:i:s', $ts) : cwe_default_valid_until(90);
                }
                $entry_arr = [
                    'value' => $ip_input, 'comment' => $comment, 'date' => $date_string,
                    'fqdn' => $fqdn, 'jira' => $jira, 'tlp' => $tlp_in,
                    'type' => $ioc_type,
                    'added_by' => cwe_current_user() ?: 'unknown',
                    'confidence' => $conf_in, 'valid_until' => $vu_in,
                ];
                file_put_contents($file_path, cwe_format_blacklist_entry($entry_arr) . "\n", FILE_APPEND);
                audit_log_event('blacklist_add', ['entry'=>$ip_input, 'tlp'=>$tlp_in, 'type'=>$ioc_type, 'confidence'=>$conf_in, 'valid_until'=>$vu_in]);
                $_SESSION['message'] .= "Kayıt başarıyla eklendi: " . cwe_msg_escape($ip_input) . " (tür: " . cwe_msg_escape($ioc_type) . ", TLP: " . cwe_msg_escape($tlp_in) . ", conf: $conf_in, expires: " . cwe_msg_escape($vu_in) . ")<br>";
                rebuild_firewall_feed();
            }
        }
    }
}

// Excel ile toplu ekleme işlemi
// CSV bulk import — basit CSV parse, mevcut $_POST['ip_address'] handler'a yönlendir
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['csv_file']) && $_FILES['csv_file']['error'] === UPLOAD_ERR_OK) {
    $tmp = $_FILES['csv_file']['tmp_name'];
    $rows = [];
    $imported = 0; $skipped = 0; $errs = [];
    if (($fh = @fopen($tmp, 'r')) !== false) {
        $hdr = fgetcsv($fh); // header satırı (varsa value,comment,tlp benzeri)
        $has_header = $hdr && count($hdr) > 0 && !filter_var($hdr[0], FILTER_VALIDATE_IP) && strpos($hdr[0] ?? '', '.') === false;
        if (!$has_header) rewind($fh);
        while (($r = fgetcsv($fh)) !== false) {
            $val = trim($r[0] ?? '');
            $cmt = trim($r[1] ?? 'CSV import');
            if ($val === '' || $val[0] === '#') continue;
            // basit validation
            $ipPart = explode('/', $val)[0];
            $ok = filter_var($ipPart, FILTER_VALIDATE_IP) || (filter_var($val, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) && strpos($val, '.') !== false);
            if (!$ok) { $errs[] = $val; $skipped++; continue; }
            // dedupe
            $existing = file_exists($file_path) ? file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            $found = false;
            foreach ($existing as $line) { if (trim(explode('|', $line)[0]) === $val) { $found = true; break; } }
            if ($found) { $skipped++; continue; }
            // R41 (T4.1): CSV warninglist guard (override = 4. col == '1' veya 'override')
            $row_override = !empty($r[4]) && in_array(strtolower(trim($r[4])), ['1','override','yes','true'], true);
            $wl_match_csv = cwe_warninglist_match($val);
            if ($wl_match_csv && !$row_override) {
                $errs[] = "warninglist:{$val}";
                $skipped++; continue;
            } elseif ($wl_match_csv && $row_override) {
                audit_log_event('warninglist_override', ['entry'=>$val, 'match'=>$wl_match_csv, 'source'=>'csv-import']);
            }
            // R28 (T1.2): CSV row → 10-field schema, type auto-detect
            $row_tlp  = strtoupper(trim($r[2] ?? 'WHITE'));
            $row_conf = isset($r[3]) && $r[3] !== '' ? (int)$r[3] : 60;
            $entry_arr = [
                'value' => $val, 'comment' => $cmt, 'date' => date('Y-m-d H:i:s'),
                'fqdn' => '', 'jira' => '', 'tlp' => $row_tlp,
                'type' => cwe_detect_type($val),
                'added_by' => 'csv:' . (cwe_current_user() ?: 'unknown'),
                'confidence' => $row_conf,
                'valid_until' => cwe_default_valid_until(90),
            ];
            file_put_contents($file_path, cwe_format_blacklist_entry($entry_arr) . "\n", FILE_APPEND);
            file_put_contents('/var/www/html/cyberwebeyeosblacklist.txt', $val . "\n", FILE_APPEND);
            $imported++;
        }
        fclose($fh);
    }
    audit_log_event('csv_import', ['imported'=>$imported, 'skipped'=>$skipped]);
    $_SESSION['message'] = "📥 CSV: <strong>$imported</strong> eklendi, $skipped atlandı" . ($errs ? " (ilk hatalar: " . htmlspecialchars(implode(', ', array_slice($errs, 0, 5))) . ")" : "");
    header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=blacklist');
    exit;
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['excel_file'])) {
    $file = $_FILES['excel_file']['tmp_name'];
    $excelData = \PhpOffice\PhpSpreadsheet\IOFactory::load($file);
    $sheet = $excelData->getActiveSheet();

    $successful_entries = [];
    $error_messages = [];

    foreach ($sheet->getRowIterator() as $row) {
        $cellIterator = $row->getCellIterator();
        $cellIterator->setIterateOnlyExistingCells(false);

        $rowData = [];
        foreach ($cellIterator as $cell) {
            $rowData[] = $cell->getValue();
        }

        $ip = trim($rowData[0]);
        $comment = trim($rowData[1]);
        $fqdn = trim($rowData[2]);
        $jira = trim($rowData[3]);

        if (!empty($ip)) {
            if (strpos($ip, '/') !== false) {
                $ip = explode('/', $ip)[0];
            } else {
                $ip .= '/32';
            }
            // Özel IP kontrolü
                        if (is_private_ip(explode('/', $ip)[0])) {
                $error_messages[] = "Özel IP adresi (Private IP) eklenemez: " . cwe_msg_escape($ip);
                continue; // Özel IP'yi atla
            }
            // cyberwebeyeos IP bloklarına ait mi kontrol et
                        if (is_cyberwebeyeos_ip($ip)) {
                $error_messages[] = "Bu IP, cyberwebeyeos ortamına aittir ve eklenemez: " . cwe_msg_escape($ip);
                continue;
            }
            // IP geçerlilik kontrolü
                        if (!validate_ip($ip)) {
                $error_messages[] = "Geçersiz IP adresi veya subnet prefix: " . cwe_msg_escape($ip);
                continue; // Geçersizse bir sonraki satıra geç
            } elseif (ip_exists($ip) || subnet_exists($ip)) {
                $error_messages[] = "Bu IP adresi veya subnet zaten mevcut: " . cwe_msg_escape($ip);
                continue; // Zaten mevcutsa bir sonraki satıra geç
            }
        }

        // FQDN doğrulama
                if (!empty($fqdn)) {
            if (!validate_fqdn($fqdn)) {
                $error_messages[] = "Geçersiz FQDN: " . cwe_msg_escape($fqdn);
                continue; // Geçersizse bir sonraki satıra geç
            } elseif (fqdn_exists($fqdn)) {
                $error_messages[] = "Bu FQDN zaten mevcut: " . cwe_msg_escape($fqdn);
                continue; // Zaten mevcutsa bir sonraki satıra geç
            }
        }

        // IP'yi prefix formatına çevir
                $ip_prefix = empty($ip) ? 'N/A' : convert_ip_to_prefix($ip);
        // Yeni giriş ekleme
                $date = new DateTime('now', new DateTimeZone('Europe/Istanbul'));
        $date_string = $date->format('Y-m-d H:i:s');

        // IP varsa kaydet
                if (!empty($ip)) {
            $new_entry = "$ip_prefix|$comment|$date_string|$fqdn|$jira\n";
            file_put_contents($file_path, $new_entry, FILE_APPEND);
            // cyberwebeyeosblacklist.txt dosyasına yazma
                        rebuild_firewall_feed();
        } elseif (!empty($fqdn)) {
            // FQDN eklerken IP yoksa "N/A" kullan
                        $new_entry = "N/A|$comment|$date_string|$fqdn|$jira\n";
            file_put_contents($file_path, $new_entry, FILE_APPEND);
            rebuild_firewall_feed();
        }
        $successful_entries[] = !empty($ip) ? $ip : $fqdn; // Başarıyla eklenen girişleri diziye ekle
    }

    // Bildirim oluştur
        $messages = [];
    if (!empty($successful_entries)) {
        audit_log_event('blacklist_add', ['entries'=>$successful_entries]);
        $messages[] = "Başarıyla eklendi: " . cwe_msg_escape(implode(', ', $successful_entries));
    }
    if (!empty($error_messages)) {
        $messages[] = "Aşağıdaki girişler eklenemedi:<br>" . implode('<br>', $error_messages);
    }
    $_SESSION['message'] = implode('<br>', $messages);
}

// G�ncellenmis write_to_cyberwebeyeos_blacklist fonksiyonu
function write_to_cyberwebeyeos_blacklist($ip, $fqdn) {
    $output_file = '/var/www/html/cyberwebeyeosblacklist.txt';
    
    // Mevcut i�erigi oku ve sadece IP'leri al
    $existing_ips = [];
    if (file_exists($output_file)) {
        $existing_lines = file($output_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($existing_lines as $line) {
            // Eger satirda | varsa, sadece IP kismini al
            $parts = explode("|", $line);
            $clean_ip = trim($parts[0]);
            if ($clean_ip) {
                $existing_ips[] = $clean_ip;
            }
        }
    }
    
    $changes_made = false;
    
    // IP'yi ekle (N/A degilse ve zaten mevcut degilse)
    if (!empty($ip) && $ip !== 'N/A' && !in_array(trim($ip), $existing_ips)) {
        $existing_ips[] = trim($ip);
        $changes_made = true;
    }
    
    // FQDN'i ekle (bos degilse ve zaten mevcut degilse)
    if (!empty($fqdn) && !in_array(trim($fqdn), $existing_ips)) {
        $existing_ips[] = trim($fqdn);
        $changes_made = true;
    }
    
    // Degisiklik yapildiysa dosyayi sadece IP'lerle yeniden yaz
    if ($changes_made) {
        file_put_contents($output_file, implode("\n", $existing_ips) . "\n");
    }
    
    return $changes_made;
}

// G�ncellenmis sync_manual_blacklist_to_cyberwebeyeos fonksiyonu
function sync_manual_blacklist_to_cyberwebeyeos() {
    global $file_path;
    $output_file = '/var/www/html/cyberwebeyeosblacklist.txt';
    
    // Manuel listeyi oku
    $manual_items = file_exists($file_path) ? file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    
    // Mevcut cyberwebeyeosblacklist.txt i�erigini oku ve sadece IP'leri al
    $existing_ips = [];
    if (file_exists($output_file)) {
        $existing_lines = file($output_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($existing_lines as $line) {
            // Eger satirda | varsa, sadece IP kismini al
            $parts = explode("|", $line);
            $clean_ip = trim($parts[0]);
            if ($clean_ip) {
                $existing_ips[] = $clean_ip;
            }
        }
    }
    
    $changes_made = false;
    
    // Manuel listedeki her �geyi isle
    foreach ($manual_items as $item) {
        $parts = explode("|", $item);
        if (count($parts) >= 1) {
            $ip = trim($parts[0]);
            $fqdn = isset($parts[3]) ? trim($parts[3]) : '';
            
            // IP'yi ekle (N/A degilse ve zaten mevcut degilse)
            if ($ip && $ip !== 'N/A' && !in_array($ip, $existing_ips)) {
                $existing_ips[] = $ip;
                $changes_made = true;
            }
            
            // FQDN'i ekle (bos degilse ve zaten mevcut degilse)
            if ($fqdn && !in_array($fqdn, $existing_ips)) {
                $existing_ips[] = $fqdn;
                $changes_made = true;
            }
        }
    }
    
    // Degisiklik yapildiysa dosyayi sadece IP'lerle yeniden yaz
    if ($changes_made) {
        file_put_contents($output_file, implode("\n", $existing_ips) . "\n");
    }
    
    return $changes_made;
}

// Mevcut dosyayi temizlemek i�in yardimci fonksiyon (bir kerelik kullanim)
function clean_existing_cyberwebeyeos_file() {
    $output_file = '/var/www/html/cyberwebeyeosblacklist.txt';
    
    if (file_exists($output_file)) {
        $lines = file($output_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $clean_ips = [];
        
        foreach ($lines as $line) {
            // Satirdan sadece IP kismini al
            $parts = explode("|", $line);
            $ip = trim($parts[0]);
            if ($ip && !in_array($ip, $clean_ips)) {
                $clean_ips[] = $ip;
            }
        }
        
        // Dosyayi sadece IP'lerle yeniden yaz
        file_put_contents($output_file, implode("\n", $clean_ips) . "\n");
        echo "Dosya temizlendi. Toplam " . count($clean_ips) . " IP/FQDN kaydedildi.\n";
        return true;
    }
    return false;
}

// clean_existing_cyberwebeyeos_file() çağrısı kaldırıldı - bu fonksiyon her sayfa yüklenişinde çalışıp performans sorununa neden oluyordu
// Gerekirse manuel olarak çağırılabilir

// ==========================================
// Yeni Eklenen: Status ve Log Fonksiyonları
// ==========================================


// Log dosyasının son satırlarını al
function get_recent_logs($lines = 10) {
    $log_file = '/var/www/html/ip_blocklist.log';

    if (!file_exists($log_file)) {
        return [];
    }

    $log_lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $recent_logs = array_slice($log_lines, -$lines);

    return array_reverse($recent_logs);
}

// Conflict log'larını al
function get_conflict_logs($lines = 5) {
    $conflict_log = '/var/www/html/conflict_log.txt';

    if (!file_exists($conflict_log)) {
        return [];
    }

    $log_content = file_get_contents($conflict_log);

    // Son N raporu al
    $reports = preg_split('/IP Listesi Uyumsuzluk Raporu - /', $log_content);
    $reports = array_filter($reports); // Boş elemanları kaldır
    $recent_reports = array_slice($reports, -$lines);

    return array_reverse($recent_reports);
}

// Kullanıcıdan arama terimini ve sayfa ayarlarını al
$search_ip = isset($_GET['search']) ? trim($_GET['search']) : '';
$per_page = isset($_GET['per_page']) ? (int)$_GET['per_page'] : 10;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
// SPRINT7-T8: Accept ?list= (from hash routing) OR legacy ?list_filter=
$list_filter = isset($_GET['list']) && $_GET['list'] !== ''
    ? trim($_GET['list'])
    : (isset($_GET['list_filter']) ? trim($_GET['list_filter']) : 'all');
$per_page_options = [10, 25, 50, 100];
// R88e: vanilla fetch fragment-only response — sidebar/KPI/topbar yeniden render edilmeyecek
$__is_fragment = isset($_GET['fragment']) && $_GET['fragment'] === 'blacklist-grid';
// Fragment modunda outer layout output buffer'da yutulur, #bl-content açılırken flush'lanır
if ($__is_fragment) { @ob_start(); }
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo htmlspecialchars($instance_name); ?></title>
<link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code&display=optional" rel="stylesheet">
<!-- R88e: htmx kaldırıldı — vanilla fetch + min-height CSS (4-agent debate winner) -->
<style>
  :root {
    /* Primary (Tabler blue — security-grade, WCAG AA) */
    --brand-50:  #e7f1fa;
    --brand-100: #c8e0f4;
    --brand-200: #98c4e8;
    --brand-300: #65a4d9;
    --brand-400: #3a8aca;
    --brand-500: #1971c2;
    --brand-600: #1862a6;
    --brand-700: #15518a;
    --brand-800: #11406d;
    --brand-900: #0d2f51;

    /* Status colors — Tabler / WCAG AA */
    --success:    #2f9e44;
    --success-bg: #d3f9d8;
    --warning:    #e67700;
    --warning-bg: #fff4e0;
    --danger:     #c92a2a;
    --danger-bg:  #ffe3e3;
    --info:       #0c8599;
    --info-bg:    #c5f6fa;

    /* Surface + text — Nord-derived */
    --surface: #ffffff;
    --bg-page: #f4f6fa;
    --text:        #1a2332;
    --text-muted:  #5a6a7e;
    --slate-50:  #f7f9fc;
    --slate-100: #eef2f7;
    --slate-200: #dce3ea;
    --slate-300: #c4cfdb;
    --slate-400: #94a3b8;
    --slate-500: #5a6a7e;
    --slate-600: #475569;
    --slate-700: #334155;
    --slate-800: #1f2937;
    --slate-900: #182433;

    --bg:var(--slate-100); --surface:#fff; --border:var(--slate-200);
    --shadow-sm:0 1px 2px rgba(15,23,42,.04);
    --shadow:0 1px 3px rgba(15,23,42,.06),0 1px 2px rgba(15,23,42,.04);
    --shadow-md:0 4px 6px -1px rgba(15,23,42,.08),0 2px 4px -1px rgba(15,23,42,.05);
    --shadow-lg:0 10px 20px rgba(15,23,42,.10);
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  /* R89b: CLS=0 pattern — sayfa toplam boyu DAİMA 100vh; iç scroll .main-pane'de */
  html{-webkit-font-smoothing:antialiased;height:100%;overflow:hidden;}
  /* R88a: Inter Fallback — system font metric override; Inter yüklenene kadar swap shift sıfır. */
  @font-face{font-family:'Inter Fallback';src:local('Arial'),local('Helvetica'),local('sans-serif');size-adjust:107%;ascent-override:90%;descent-override:22%;line-gap-override:0%;}
  body{font-family:'Inter','Inter Fallback',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;
       height:100vh;overflow:hidden;}
  a{color:inherit;text-decoration:none;}
  code,.mono{font-family:'Fira Code','Courier New',monospace;font-size:.875em;}
  .tabular{font-variant-numeric:tabular-nums;}

  /* R30 (T1.5): SIDEBAR LAYOUT (topbar refactor) */
  .app-shell{display:flex;height:100vh;align-items:stretch;overflow:hidden;}
  .sidebar{width:260px;flex-shrink:0;background:#182433;color:#fff;display:flex;flex-direction:column;
           height:100vh;box-shadow:2px 0 20px rgba(0,0,0,.12);z-index:50;overflow-y:auto;}
  .sidebar-head{padding:18px 16px;border-bottom:1px solid rgba(255,255,255,.06);}
  .sidebar .brand{display:flex;align-items:center;gap:11px;}
  .brand-logo{width:42px;height:42px;background:var(--brand-600);
              border-radius:11px;display:flex;align-items:center;justify-content:center;
              color:#fff;font-weight:800;font-size:20px;letter-spacing:-.02em;flex-shrink:0;
              box-shadow:none;}
  .brand-text .brand-name{font-size:15px;font-weight:700;letter-spacing:-.01em;line-height:1.1;}
  .brand-text .brand-sub{font-size:10.5px;color:var(--slate-400);letter-spacing:.04em;text-transform:uppercase;margin-top:2px;}
  .sidebar-search{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,.06);}
  .sidebar-search input{width:100%;background:var(--slate-800);color:#fff;border:1px solid var(--slate-700);border-radius:8px;
                        padding:8px 12px 8px 32px;font-size:12.5px;font-family:inherit;outline:none;transition:border-color .15s;}
  .sidebar-search input:focus{border-color:var(--brand-400);}
  .sidebar-search .search-wrap{position:relative;}
  .sidebar-search .search-wrap > i.fa-search{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--slate-400);font-size:12px;pointer-events:none;}
  .topnav{flex:1;display:flex;flex-direction:column;gap:2px;padding:10px 10px;overflow-y:auto;}
  .topnav .tab-btn{background:transparent;border:none;color:var(--slate-300);padding:10px 12px;white-space:nowrap;
                   border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;font-family:inherit;
                   display:flex;align-items:center;gap:11px;transition:background .12s,color .12s;text-align:left;}
  .topnav .tab-btn > i{width:18px;text-align:center;font-size:14px;flex-shrink:0;}
  .topnav .tab-btn > span:not(.badge-count){flex:1;}
  .topnav .tab-btn:hover{background:var(--slate-800);color:#fff;}
  .topnav .tab-btn.active{background:rgba(25,113,194,.14);color:#74b3f5;
                          box-shadow:inset 3px 0 0 #1971c2;}
  .topnav .tab-btn .badge-count{background:var(--danger);color:#fff;font-size:10px;font-weight:700;
                                 padding:1px 7px;border-radius:99px;min-width:20px;text-align:center;line-height:1.4;flex-shrink:0;}
  .sidebar-foot{padding:14px;border-top:1px solid rgba(255,255,255,.06);}
  .user-chip{display:flex;align-items:center;gap:8px;padding:7px 10px;
             background:var(--slate-800);border-radius:10px;font-size:12.5px;color:var(--slate-200);}
  .user-chip .avatar{width:28px;height:28px;border-radius:50%;flex-shrink:0;
                     background:var(--brand-600);
                     display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:12px;}
  .user-chip > span:not([title]):not(.badge-count){flex:1;overflow:hidden;text-overflow:ellipsis;}
  .user-chip a.logout{color:var(--slate-400);padding:4px 6px;border-radius:6px;}
  .user-chip a.logout:hover{color:#fff;background:var(--slate-700);}
  .main-pane{flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;overflow:auto;contain:layout paint;}
  /* Hamburger (mobile) */
  .hamburger{display:none;position:fixed;top:14px;left:14px;z-index:60;background:var(--slate-900);color:#fff;border:none;
             width:42px;height:42px;border-radius:10px;font-size:18px;cursor:pointer;box-shadow:var(--shadow-md);}
  .sidebar-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:45;}
  .sidebar-backdrop.open{display:block;}

  /* STICKY PENDING BANNER */
  .pending-banner{background:var(--warning-bg);border-bottom:1px solid #fde68a;
                  padding:10px 24px;display:flex;align-items:center;justify-content:space-between;
                  gap:12px;position:sticky;top:0;z-index:40;}
  .pending-banner .pb-text{font-size:13px;color:#92400e;}
  .pending-banner .pb-text strong{color:#78350f;}

  /* CONTAINER */
  .container{max-width:1180px;margin:0 auto;padding:28px;}

  /* KPI GRID */
  .kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin-bottom:22px;contain:layout;}
  .kpi{background:var(--surface);border:1px solid var(--border);border-radius:6px;
       padding:18px 20px;position:relative;transition:box-shadow .15s;cursor:pointer;min-height:112px;}
  .kpi:hover{box-shadow:var(--shadow-md);}
  .kpi-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;
             letter-spacing:.08em;font-weight:600;margin-bottom:8px;}
  .kpi-value{font-size:28px;font-weight:700;color:var(--text);line-height:1;
             font-variant-numeric:tabular-nums;}
  .kpi-delta{font-size:11px;color:var(--text-muted);margin-top:6px;}
  .kpi-icon{position:absolute;top:16px;right:16px;width:38px;height:38px;border-radius:10px;
            display:flex;align-items:center;justify-content:center;font-size:16px;}
  .kpi-icon.brand{background:var(--brand-50);color:var(--brand-700);}
  .kpi-icon.amber{background:var(--warning-bg);color:var(--warning);}
  .kpi-icon.info{background:var(--info-bg);color:var(--info);}
  .kpi-icon.green{background:var(--success-bg);color:var(--success);}
  .kpi-icon.danger{background:var(--danger-bg);color:var(--danger);}

  /* CARDS */
  .card{background:var(--surface);border:1px solid var(--border);border-radius:6px;
        overflow:hidden;box-shadow:var(--shadow-sm);}
  .card+.card{margin-top:24px;}
  .card-head{padding:14px 18px;border-bottom:1px solid var(--border);
             display:flex;align-items:center;justify-content:space-between;gap:12px;}
  .card-head h2{font-size:14px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;}
  .card-head .h2-icon{width:26px;height:26px;border-radius:7px;background:var(--brand-50);
                      color:var(--brand-700);display:flex;align-items:center;justify-content:center;font-size:13px;}
  .card-head .h2-icon.amber{background:var(--warning-bg);color:var(--warning);}
  .card-head .h2-icon.green{background:var(--success-bg);color:var(--success);}
  .card-head .h2-icon.info{background:var(--info-bg);color:var(--info);}
  .card-head .h2-icon.slate{background:var(--slate-100);color:var(--slate-600);}
  .card-actions{display:flex;gap:6px;}
  .card-body{padding:18px;} /* already >=18px — satisfies Change 4 */
  .card-body.flush{padding:0;}

  /* MAIN GRID */
  .main-grid{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:20px;}

  /* SPRINT7-T6: Multi-list sidebar
     R85-bis (S7.5-Drawer): Grid daima 2-kolon (sidebar + content).
     Sağ aside artık overlay drawer — grid'i daraltmıyor. */
  .main-grid--with-listnav {
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      gap: 16px;
      contain: layout;
  }
  @media (max-width: 1400px) {
      .main-grid--with-listnav {
          grid-template-columns: 220px minmax(0, 1fr);
      }
  }
  @media (max-width: 1024px) {
      .main-grid--with-listnav {
          grid-template-columns: 1fr;
      }
      .main-grid--with-listnav > aside.listnav { display: none; }
  }

  /* R85-bis (S7.5-Drawer): Overlay slide-over drawer (D pattern:
     Supabase row-insert + Stripe FocusView + Adobe slideout + Carbon slide-over). */
  .bl-drawer {
      position: fixed;
      top: 0; right: 0;
      width: 440px;
      height: 100vh;
      background: var(--bs-body-bg, #fff);
      box-shadow: -4px 0 16px rgba(0,0,0,0.12);
      transform: translateX(100%);
      transition: transform 200ms ease-out;
      z-index: 1050;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
  }
  .bl-drawer.open { transform: translateX(0); }
  .bl-drawer[hidden] { display: none; }
  .bl-drawer.open[hidden] { display: flex; }
  .bl-drawer-backdrop {
      position: fixed; inset: 0;
      background: rgba(0,0,0,0.3);
      opacity: 0;
      transition: opacity 200ms ease-out;
      z-index: 1040;
  }
  .bl-drawer-backdrop.open { opacity: 1; }
  .bl-drawer-backdrop[hidden] { display: none; }
  .bl-drawer-head {
      display: flex; justify-content: space-between; align-items: center;
      padding: 16px 20px;
      border-bottom: 1px solid var(--slate-200);
      flex-shrink: 0;
  }
  .bl-drawer-head h3 {
      margin: 0; font-size: 15px; font-weight: 600; color: var(--text);
  }
  .bl-drawer-body { padding: 16px 20px; flex: 1; }
  .bl-drawer-close {
      background: none; border: 0; font-size: 24px; cursor: pointer;
      padding: 4px 8px; line-height: 1; color: var(--text-muted);
  }
  .bl-drawer-close:hover { color: var(--text); }
  body.drawer-open { overflow: hidden; }
  @media (max-width: 1024px) {
      .bl-drawer { width: 100%; }
  }

  /* R84 (UX Pass-2 §1-2): Expandable row + responsive col-tarih */
  .bl-row { cursor: pointer; }
  .bl-row .bl-chevron { transition: transform .15s ease; }
  .bl-row.expanded .bl-chevron { transform: rotate(90deg); color: var(--brand-500); }
  .bl-row-detail.hidden { display: none; }
  .bl-row-detail > td {
      background: var(--slate-50);
      padding: 0 16px !important;
      border-bottom: 1px solid var(--slate-100);
  }
  .bl-row-detail .row-detail-inner {
      max-height: 0;
      overflow: hidden;
      transition: max-height .2s ease, padding .2s ease;
      will-change: max-height;
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.7;
  }
  .bl-row-detail:not(.hidden) .row-detail-inner {
      max-height: 200px;
      padding: 10px 0;
  }
  .bl-row-detail .row-detail-sep { color: var(--slate-300); margin: 0 4px; }
  .bl-row-detail strong { color: var(--text); font-weight: 600; }
  .bl-comment-trunc {
      display: inline-block;
      max-width: 120px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      vertical-align: middle;
  }
  /* R85-bis (S7.5-Drawer): Drawer artık overlay — tablo daralmıyor.
     Tarih kolonu daima görünür; sadece çok dar viewport'ta gizle. */
  @media (max-width: 1280px) {
      .col-tarih { display: none; }
  }
  @media (max-width: 800px) {
      .bl-actions .btn { font-size: 0 !important; padding: 6px 8px !important; }
      .bl-actions .btn i { font-size: 12px; }
      .bl-actions .btn::after { font-size: 11px; }
  }

  /* R84 (UX Pass-2 §3): External/dynamic inline banner */
  .bl-external-notice {
      margin: 12px 18px;
      padding: 10px 14px;
      background: var(--info-bg, #dbeafe);
      border: 1px solid #93c5fd;
      border-left: 3px solid #2563eb;
      border-radius: 6px;
      color: #1e40af;
      font-size: 12.5px;
      line-height: 1.55;
  }
  .bl-external-notice a { color: #1d4ed8; font-weight: 600; }

  /* R84 (UX Pass-2 §5): Bilgi <details> disclosure */
  .bl-info-disclosure {
      border: 1px solid var(--slate-200);
      border-radius: 6px;
      padding: 10px 14px;
      margin-top: 12px;
      background: var(--surface);
  }
  .bl-info-disclosure summary {
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
      color: var(--text);
      user-select: none;
      list-style: none;
  }
  .bl-info-disclosure summary::-webkit-details-marker { display: none; }
  .bl-info-disclosure summary::before {
      content: '▶';
      display: inline-block;
      margin-right: 6px;
      font-size: 9px;
      color: var(--text-muted);
      transition: transform .15s ease;
  }
  .bl-info-disclosure[open] summary::before { transform: rotate(90deg); }
  .listnav {
      background: var(--surface);
      border: 1px solid var(--slate-200);
      border-radius: 6px;
      padding: 14px 10px;
      font-size: 13px;
      max-height: calc(100vh - 200px);
      overflow-y: auto;
  }
  .listnav section { margin-bottom: 20px; }
  .listnav section:last-child { margin-bottom: 0; }
  .listnav section h3 {
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin: 0 0 10px 6px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--slate-100);
      display: flex;
      justify-content: space-between;
      align-items: center;
  }
  .listnav .section-count {
      background: var(--slate-100);
      color: var(--text-muted);
      padding: 1px 7px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0;
  }
  .listnav ul { list-style: none; padding: 0; margin: 0; }
  .listnav li {
      display: flex;
      align-items: center;
      padding: 7px 10px;
      border-radius: 5px;
      cursor: pointer;
      transition: background 0.12s;
      margin-bottom: 2px;
      font-size: 13px;
  }
  .listnav li:hover { background: var(--slate-50); }
  .listnav li.active {
      background: var(--brand-50);
      color: var(--brand-700);
      font-weight: 600;
      box-shadow: inset 3px 0 0 var(--brand-500);
  }
  .listnav li a {
      color: inherit;
      text-decoration: none;
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
  }
  .listnav li .item-count {
      background: var(--slate-100);
      color: var(--text-muted);
      padding: 1px 8px;
      border-radius: 10px;
      font-size: 10.5px;
      font-weight: 600;
      margin-left: 8px;
      flex-shrink: 0;
      min-width: 42px;
      text-align: center;
      font-variant-numeric: tabular-nums;
  }
  .listnav li.active .item-count {
      background: var(--brand-100);
      color: var(--brand-700);
  }
  .listnav li .ln-actions { display: none; gap: 4px; margin-left: 6px; flex-shrink: 0; }
  .listnav li:hover .ln-actions { display: flex; }
  .listnav li .ln-actions button {
      background: var(--slate-50);
      border: 1px solid var(--slate-200);
      cursor: pointer;
      padding: 2px 6px;
      font-size: 11px;
      color: var(--text-muted);
      border-radius: 3px;
      line-height: 1;
  }
  .listnav li .ln-actions button:hover { background: var(--slate-100); color: var(--text); border-color: var(--slate-300); }

  /* TABLE STYLING (override display_blacklist output) */
  .search-bar{padding:12px 18px;border-bottom:1px solid var(--border);background:var(--slate-50);}
  .search-table{width:100%;}
  .search-table td:first-child{padding-right:8px;}
  .search-bar input[type=text]{width:100%;padding:8px 12px;border:1px solid var(--slate-300);
                                border-radius:7px;font-size:13px;font-family:inherit;background:#fff;}
  .search-bar input[type=text]:focus{outline:2px solid var(--brand-500);outline-offset:1px;border-color:var(--brand-500);}
  .action-bar{padding:10px 18px;border-bottom:1px solid var(--border);background:#fff;
              display:flex;flex-wrap:wrap;gap:16px;align-items:center;}
  .action-bar label{font-size:12px;color:var(--text-muted);margin-right:6px;}
  .action-bar select{padding:6px 10px;border:1px solid var(--slate-300);border-radius:6px;
                     font-size:12.5px;font-family:inherit;background:#fff;}
  .filter-section,.per-page-section{display:flex;align-items:center;}
  .table-responsive{overflow-x:auto;}
  .data-table{width:100%;border-collapse:collapse;font-size:13px;}
  .data-table thead th{background:var(--slate-50);padding:11px 16px;text-align:left;
                        font-weight:600;font-size:11px;text-transform:uppercase;
                        letter-spacing:.06em;color:var(--text-muted);
                        border-bottom:1px solid var(--border);white-space:nowrap;position:sticky;top:0;}
  .data-table tbody td{padding:11px 16px;border-bottom:1px solid var(--slate-100);
                       vertical-align:middle;color:var(--text);}
  .data-table tbody tr:hover{background:var(--brand-50);}
  .data-table tbody tr:last-child td{border-bottom:none;}
  .data-table input[type=checkbox]{cursor:pointer;}
  .no-records{text-align:center;padding:40px 20px;color:var(--text-muted);font-size:13px;}

  /* BADGES */
  .badge{display:inline-block;padding:3px 9px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:.02em;line-height:1.2;}
  .badge-manual{background:var(--brand-50);color:var(--brand-700);}
  .badge-pending{background:var(--warning-bg);color:#92400e;}
  .badge-usom{background:var(--info-bg);color:#1e40af;}
  .badge-whitelist{background:var(--success-bg);color:#065f46;}
  .badge-source{background:var(--slate-100);color:var(--slate-700);}

  /* BUTTONS */
  .btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;
       border:1px solid transparent;border-radius:5px;font-size:13px;
       font-weight:500;cursor:pointer;font-family:inherit;
       text-decoration:none;transition:background .12s,color .12s,border-color .12s;white-space:nowrap;}
  .btn-primary{background:var(--brand-700);color:#fff;}
  .btn-primary:hover{background:var(--brand-600);}
  .btn-ghost{background:#fff;color:var(--text);border-color:var(--slate-300);}
  .btn-ghost:hover{background:var(--slate-50);border-color:var(--slate-400);}
  .btn-danger{background:var(--danger);color:#fff;}
  .btn-danger:hover{background:#dc2626;}
  .btn-warning{background:var(--warning);color:#fff;}
  .btn-warning:hover{background:#d97706;}
  .btn-success{background:var(--success);color:#fff;}
  .btn-success:hover{background:#059669;}
  .btn-info{background:var(--info);color:#fff;}
  .btn-info:hover{background:#2563eb;}
  .btn-sm{padding:5px 10px;font-size:12px;}
  .btn-block{width:100%;justify-content:center;}
  .btn:disabled{opacity:.55;cursor:not-allowed;}
  .btn-edit{background:var(--info);color:#fff;border:none;font-size:12px;padding:5px 10px;border-radius:5px;cursor:pointer;}
  .btn-edit:hover{background:#2563eb;}
  .btn-delete{background:var(--danger);color:#fff;border:none;font-size:12px;padding:5px 10px;border-radius:5px;cursor:pointer;}
  .btn-delete:hover{background:#dc2626;}

  /* FORMS */
  .field{margin-bottom:12px;}
  .field label{display:block;font-size:12px;font-weight:500;color:var(--text-muted);margin-bottom:5px;}
  .field input,.field textarea,.field select,
  .form-control{width:100%;padding:8px 12px;border:1px solid var(--slate-300);border-radius:5px;
                font-size:13px;font-family:inherit;background:#fff;transition:border-color .12s;}
  .field input:focus,.field textarea:focus,.field select:focus,
  .form-control:focus{outline:2px solid var(--brand-500);outline-offset:1px;border-color:var(--brand-500);}
  .field-help{font-size:11px;color:var(--text-muted);margin-top:4px;}
  .form-group{margin-bottom:14px;}
  .form-group label{display:block;font-size:12px;font-weight:500;color:var(--text-muted);margin-bottom:5px;}

  /* ADVANCED FIELDS ACCORDION */
  .advanced-toggle{font-size:12px;color:var(--text-muted);padding:8px 0;cursor:pointer;user-select:none;display:flex;align-items:center;gap:4px;}
  .advanced-toggle:hover{color:var(--text);}
  .advanced-fields{display:none;padding-top:4px;border-top:1px solid var(--slate-100);margin-top:4px;}
  .advanced-fields.open{display:block;}

  /* FILE UPLOAD */
  .file-upload{position:relative;}
  .file-upload-label{display:inline-flex;align-items:center;gap:6px;padding:7px 12px;
                     background:var(--slate-100);color:var(--text);border:1px solid var(--slate-300);
                     border-radius:6px;font-size:12.5px;cursor:pointer;width:100%;justify-content:center;}
  .file-upload-label:hover{background:var(--slate-200);}
  .file-upload input[type=file]{position:absolute;left:-9999px;opacity:0;}
  .file-name{margin-left:8px;font-size:12px;color:var(--text-muted);}

  /* NAV LIST (sidebar internal nav) */
  .nav-list{padding:6px;}
  .nav-list a,.nav-list button.nav-item{display:flex;align-items:center;gap:10px;padding:9px 11px;border-radius:7px;
                color:var(--text);font-size:13px;transition:background .12s;
                background:transparent;border:none;width:100%;text-align:left;cursor:pointer;font-family:inherit;}
  .nav-list a:hover,.nav-list button.nav-item:hover{background:var(--slate-50);}
  .nav-list a .nav-icon,.nav-list button .nav-icon{width:18px;color:var(--text-muted);text-align:center;}

  /* TOAST */
  .toast-stack{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;}
  .toast{background:#fff;border:1px solid var(--border);border-left:4px solid var(--success);
         border-radius:6px;padding:12px 16px;box-shadow:var(--shadow-lg);
         min-width:280px;max-width:380px;font-size:13px;
         display:flex;align-items:flex-start;gap:10px;}
  .toast.success{border-left-color:var(--success);}
  .toast.error{border-left-color:var(--danger);}
  .toast.warning{border-left-color:var(--warning);}
  .toast.info{border-left-color:var(--info);}
  .toast .close{background:transparent;border:none;cursor:pointer;color:var(--text-muted);font-size:16px;margin-left:auto;}

  /* ALERT (banner-style) */
  .alert{padding:12px 16px;border-radius:8px;background:var(--info-bg);color:#1e40af;
         border:1px solid #bfdbfe;margin-bottom:16px;display:flex;align-items:flex-start;justify-content:space-between;}
  .alert .close{background:transparent;border:none;cursor:pointer;color:inherit;font-size:18px;}
  .alert-info{background:var(--info-bg);color:#1e40af;border-color:#bfdbfe;}
  .alert-warning{background:var(--warning-bg);color:#92400e;border-color:#fde68a;}
  .alert-success{background:var(--success-bg);color:#065f46;border-color:#a7f3d0;}
  .alert-danger{background:var(--danger-bg);color:#991b1b;border-color:#fecaca;}

  /* PAGINATION */
  .pagination{display:flex;justify-content:center;gap:4px;padding:14px;flex-wrap:wrap;}
  .pagination a,.pagination span{padding:6px 11px;border:1px solid var(--border);
                                  border-radius:6px;color:var(--text);font-size:12.5px;
                                  min-width:30px;text-align:center;background:#fff;}
  .pagination .current{background:var(--brand-700);color:#fff;border-color:var(--brand-700);}
  .pagination a:hover{background:var(--slate-50);}

  /* TAB PANEL SYSTEM */
  .tab-panel{display:none;}
  .tab-panel.active{display:block;}
  /* R88a: animation:fadeIn kaldırıldı — her tab switch'te 4px translateY shift'i sebep oluyordu. @keyframes silinmedi (başka kullanım audit edilebilir). */
  @keyframes fadeIn{from{opacity:0;transform:translateY(4px);}to{opacity:1;transform:translateY(0);}}
  @keyframes slideUp{from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);}}
  @keyframes pulse{0%,100%{opacity:1;}50%{opacity:.6;}}
  @keyframes shimmer{0%{background-position:-200% 0;}100%{background-position:200% 0;}}

  /* Visual polish — flat design (gradients removed) */
  .kpi{background:var(--surface);border:1px solid var(--slate-200);border-radius:6px;}
  .kpi-icon{transition:transform .25s;}
  .card{transition:box-shadow .2s;}
  .card:hover{box-shadow:var(--shadow-md);}
  .topbar{background:var(--slate-900);border-bottom:1px solid var(--slate-800);}
  .pending-banner{background:var(--warning-bg);}
  .badge-count{box-shadow:none;}
  .btn-primary{background:var(--brand-500);box-shadow:none;}
  .btn-primary:hover{background:var(--brand-600);}
  .btn-success{background:var(--success);}
  .btn-warning{background:var(--warning);}
  .btn-danger{background:var(--danger);}
  .brand-logo{position:relative;overflow:hidden;}
  .data-table tbody tr{transition:background .12s;}
  .data-table tbody tr:hover{background:var(--brand-50);}
  .tab-btn{position:relative;}
  .tab-btn.active::after{content:'';position:absolute;left:12px;right:12px;bottom:-2px;height:2px;background:var(--brand-500);border-radius:2px;}
  /* Flat data-table thead */
  .data-table thead th{background:var(--slate-50);}

  /* EMPTY STATE */
  .empty{text-align:center;padding:56px 20px;color:var(--text-muted);}
  .empty-icon{font-size:42px;color:var(--success);margin-bottom:12px;}
  .empty-icon.muted{color:var(--slate-300);}
  .empty-title{font-size:15px;font-weight:600;color:var(--text);margin-bottom:4px;}
  .empty-desc{font-size:12.5px;}

  /* USOM EMBED */
  .usom-frame-wrap{padding:0;background:var(--slate-100);}
  .usom-frame{width:100%;min-height:800px;border:none;background:#fff;}

  /* LOG VIEW */
  .log-list{font-family:'Fira Code',monospace;font-size:12px;background:var(--slate-900);color:var(--slate-100);
            padding:14px 18px;border-radius:8px;max-height:340px;overflow-y:auto;line-height:1.7;}
  .log-list .log-line{padding:2px 0;}

  /* FOOTER */
  .footer{text-align:center;padding:22px;color:var(--text-muted);font-size:12px;
          border-top:1px solid var(--border);margin-top:32px;background:#fff;}
  .footer a{color:var(--brand-700);}

  /* INLINE CONFIRM (delete) */
  .confirm-inline{display:inline-flex;gap:4px;align-items:center;}

  /* RESPONSIVE — R30 (T1.5) sidebar layout */
  @media (max-width: 1024px){
    .main-grid{grid-template-columns:1fr;}
    .kpi-row{grid-template-columns:repeat(2,1fr);}
    .hamburger{display:flex;align-items:center;justify-content:center;}
    .sidebar{position:fixed;left:-280px;top:0;height:100vh;width:260px;transition:left .25s ease;}
    .sidebar.open{left:0;}
    .container{padding-top:72px;}
  }
  @media (max-width: 640px){
    .container{padding-left:14px;padding-right:14px;padding-top:72px;}
    .kpi-row{grid-template-columns:1fr;}
    .pending-banner{flex-direction:column;align-items:flex-start;}
  }

  /* R89b: vanilla loading indicator — absolute, akıştan çık (swap'ta yer açıp kapatmaz) */
  .bl-loading-indicator{
    display:none;
    position:fixed;
    top:14px;
    right:18px;
    z-index:100;
    padding:6px 12px;
    background:var(--brand-50);
    color:var(--brand-700);
    border-radius:6px;
    font-size:12px;
    box-shadow:0 2px 8px rgba(0,0,0,0.1);
  }
  .bl-loading-indicator.visible{display:block;}
  /* R88e: BUG FİX — sayfa boyu sabit kalır, swap'ta scrollbar toggle olmaz */
  #bl-content{
    position:relative;
    min-height: calc(100vh - 280px);
    transition: opacity 150ms ease-out;
  }

  /* R89a: CLS=0 temel — fixed dimensions (Plan B, markup-invasive değil) */
  /* KPI row: 4 kart × 112px + padding/gap ≈ 140px sabit */
  .kpi-row{min-height:140px;}
  /* Pending banner sticky 52px — koşullu render'da yer rezerve eden slot */
  .bl-banner-slot{min-height:50px;display:block;}
  .bl-banner-slot:empty{min-height:0;display:none;}
  /* R88e (S7.5): #bl-content min-height korunur; R89a card-head sabitlenir */
  .card>.card-head{min-height:54px;}

  /* R90: v2 cerrahi port — SADECE #tab-blacklist için.
     Diğer 9 tab (whitelist/pending/listeler/usom/catalog/users/dashboard/cve/status)
     bu rule'lardan etkilenmez. CLS=0 garantili: contain:strict + fixed grid. */
  /* R91c: Blacklist tab full viewport — body[data-tab="blacklist"] cross-browser
     (R91 :has() selector eski browser'larda çalışmıyordu). showTab() body.dataset.tab
     set ediyor → CSS parent zincirindeki tüm max-width'leri override eder.
     Diğer tab'lar (whitelist/pending/vb.) match etmediği için 1180px center korunur. */
  body[data-tab="blacklist"] .container,
  body[data-tab="blacklist"] .main-pane,
  body[data-tab="blacklist"] .app-shell {
    max-width: none !important;
    width: 100% !important;
  }
  body[data-tab="blacklist"] .container {
    padding-left: 16px !important;
    padding-right: 16px !important;
  }
  #tab-blacklist.active {
    height: calc(100vh - 200px);
    overflow: hidden;
    display: block;
    padding: 0;
    width: 100%;
  }
  #tab-blacklist:not(.active) {
    display: none;
  }
  #tab-blacklist .bl-app {
    display: grid;
    grid-template-columns: 260px 1fr;
    width: 100%;
    max-width: none;
    height: 100%;
    background: var(--surface, #fff);
    border: 1px solid var(--slate-200, #e2e8f0);
    border-radius: 10px;
    overflow: hidden;
  }
  #tab-blacklist .bl-listnav {
    overflow-y: auto;
    background: #fff;
    border-right: 1px solid var(--slate-200, #e2e8f0);
    padding: 14px 0;
    min-width: 0;
  }
  #tab-blacklist .bl-listnav .bl-section { padding: 8px 14px 4px; }
  #tab-blacklist .bl-listnav .bl-section h3 {
    font-size: 10.5px; text-transform: uppercase; letter-spacing: .07em;
    color: var(--text-muted, #64748b); margin-bottom: 6px; font-weight: 700;
    display: flex; justify-content: space-between; align-items: center;
  }
  #tab-blacklist .bl-listnav .bl-section h3 .bl-section-count {
    font-size: 10px; background: var(--slate-50, #f8fafc);
    padding: 1px 7px; border-radius: 99px; color: var(--text-muted, #64748b);
    font-weight: 600;
  }
  #tab-blacklist .bl-listnav ul { list-style: none; margin: 0; padding: 0; }
  #tab-blacklist .bl-listnav li { margin: 1px 0; }
  #tab-blacklist .bl-listnav a {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    padding: 7px 10px; border-radius: 6px; font-size: 13px;
    color: var(--text, #1a2332); transition: background .12s;
    text-decoration: none;
  }
  #tab-blacklist .bl-listnav a:hover { background: var(--slate-50, #f8fafc); }
  #tab-blacklist .bl-listnav li.active > a {
    background: rgba(25,113,194,.12); color: #15518a; font-weight: 600;
    box-shadow: inset 3px 0 0 #1971c2;
  }
  #tab-blacklist .bl-listnav .bl-count {
    font-size: 11px; color: var(--text-muted, #64748b);
    background: var(--slate-50, #f8fafc);
    padding: 1px 8px; border-radius: 99px; font-variant-numeric: tabular-nums;
  }
  #tab-blacklist .bl-listnav .bl-empty {
    font-size: 12px; color: var(--text-muted, #64748b);
    font-style: italic; padding: 4px 10px;
  }
  #tab-blacklist .bl-main {
    display: grid;
    grid-template-rows: auto 1fr;
    overflow: hidden;
    min-width: 0;
    min-height: 0;
  }
  #tab-blacklist .bl-kpi {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    padding: 14px 18px;
    border-bottom: 1px solid var(--slate-200, #e2e8f0);
    background: var(--surface, #fff);
  }
  #tab-blacklist .bl-kpi-card {
    display: flex; flex-direction: column; justify-content: center;
    padding: 10px 14px; border: 1px solid var(--slate-200, #e2e8f0);
    border-radius: 8px; background: #fff;
  }
  #tab-blacklist .bl-kpi-card.alt {
    border-color: #1971c2; background: rgba(25,113,194,.04);
  }
  #tab-blacklist .bl-kpi-card .bl-kpi-lbl {
    font-size: 11px; color: var(--text-muted, #64748b);
    text-transform: uppercase; letter-spacing: .05em; margin-bottom: 4px;
  }
  #tab-blacklist .bl-kpi-card .bl-kpi-val {
    font-size: 22px; font-weight: 700; color: var(--text, #1a2332);
    font-variant-numeric: tabular-nums;
  }
  #tab-blacklist #bl-content {
    overflow: auto;
    contain: strict;
    padding: 18px 22px;
    background: var(--bg, #f4f6fa);
    scrollbar-gutter: stable;
    min-height: 0;
    min-width: 0;
  }
  #tab-blacklist .bl-card-head {
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; flex-wrap: wrap;
    padding: 0 0 14px 0;
    border-bottom: 1px solid var(--slate-200, #e2e8f0);
    margin-bottom: 16px;
  }
  #tab-blacklist .bl-card-head h2 {
    font-size: 17px; font-weight: 700; letter-spacing: -.01em;
    display: flex; align-items: center; gap: 10px; margin: 0;
  }
  #tab-blacklist .bl-kind-tag {
    font-size: 10.5px; font-weight: 600; padding: 3px 9px; border-radius: 99px;
    text-transform: uppercase; letter-spacing: .04em;
  }
  #tab-blacklist .bl-kind-system,
  #tab-blacklist .bl-kind-manual { background: #e7f1fa; color: #15518a; }
  #tab-blacklist .bl-kind-external { background: #fff4e0; color: #8a4500; }
  #tab-blacklist .bl-kind-dynamic { background: #f3e7fa; color: #5b2a8a; }
  #tab-blacklist .bl-card-actions {
    display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  }
  #tab-blacklist .bl-add-form { margin-bottom: 14px; }
  #tab-blacklist .bl-add-form details {
    border: 1px solid var(--slate-200, #e2e8f0); border-radius: 8px;
    background: #fff;
  }
  #tab-blacklist .bl-add-form summary {
    padding: 10px 14px; cursor: pointer; font-size: 13px; font-weight: 600;
    color: #15518a; user-select: none; list-style: none;
  }
  #tab-blacklist .bl-add-form summary::-webkit-details-marker { display: none; }
  #tab-blacklist .bl-add-form summary:hover { background: var(--slate-50, #f8fafc); }
  #tab-blacklist .bl-add-form summary::before {
    content: "+ "; font-weight: 700; margin-right: 4px;
  }
  #tab-blacklist .bl-add-form details[open] summary::before { content: "− "; }
  #tab-blacklist .bl-add-form-body {
    padding: 12px 14px 14px; border-top: 1px solid var(--slate-200, #e2e8f0);
    display: grid; grid-template-columns: 1fr; gap: 8px;
  }
  #tab-blacklist .bl-add-form-body textarea {
    width: 100%; padding: 8px 10px;
    font-family: 'SF Mono', 'Fira Code', Menlo, Consolas, monospace;
    font-size: 12.5px;
    border: 1px solid var(--slate-300, #cbd5e1); border-radius: 6px;
    resize: vertical;
  }
  #tab-blacklist .bl-add-form-body input[type=text] {
    padding: 7px 10px; font-size: 13px;
    border: 1px solid var(--slate-300, #cbd5e1); border-radius: 6px;
  }
  #tab-blacklist .bl-add-help {
    font-size: 11.5px; color: var(--text-muted, #64748b); padding-top: 2px;
  }
  #tab-blacklist .bl-banner {
    padding: 10px 14px; border-radius: 7px;
    background: #fff4e0; color: #8a4500; border: 1px solid #fde68a;
    margin-bottom: 14px; font-size: 13px;
  }
  @media (max-width: 900px) {
    #tab-blacklist .bl-app { grid-template-columns: 1fr; }
    #tab-blacklist .bl-listnav {
      max-height: 200px; border-right: none;
      border-bottom: 1px solid var(--slate-200, #e2e8f0);
    }
    #tab-blacklist .bl-kpi { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>

<?php
require_once __DIR__ . '/pending_ips_helper.php';
$pending_list  = list_pending_ips();
$pending_count = count($pending_list);

function _cwe_count_data_lines($path) {
    if (!file_exists($path)) return 0;
    $n = 0;
    foreach (file($path) as $line) {
        $t = trim($line);
        if ($t !== '' && $t[0] !== '#') $n++;
    }
    return $n;
}
$manual_count    = _cwe_cached_count("/var/www/html/blacklist.txt");
$feed_count      = _cwe_cached_count("/var/www/html/cyberwebeyeosblacklist.txt");
$whitelist_count = _cwe_cached_count("/var/www/html/whitelist.txt");
$current_user    = isset($_SESSION['cwe_user']) ? $_SESSION['cwe_user'] : 'admin';

// Whitelist data (kendi tab içinde gösterilecek)
$whitelist_items = []; // each: ['entry'=>..., 'date'=>..., 'user'=>..., 'comment'=>...]
$wl_path = '/var/www/html/whitelist.txt';
if (file_exists($wl_path)) {
    foreach (file($wl_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $l) {
        $t = trim($l);
        if ($t === '' || $t[0] === '#') continue;
        $p = explode('|', $t);
        $whitelist_items[] = [
            'entry'   => trim($p[0]),
            'date'    => trim($p[1] ?? ''),
            'user'    => trim($p[2] ?? ''),
            'comment' => trim($p[3] ?? ''),
            'tlp'     => strtoupper(trim($p[4] ?? 'WHITE')),
        ];
    }
}

// USOM state
$usom_state = @json_decode(@file_get_contents('/var/www/html/usom/usom-state.json'), true) ?? [];
$usom_last_sync = $usom_state['last_sync'] ?? '—';
$usom_total     = $usom_state['file_entries'] ?? 0;
$usom_type      = $usom_state['sync_type'] ?? null;

// Recent logs
$recent_logs    = function_exists('get_recent_logs') ? get_recent_logs(15) : [];
$conflict_logs  = function_exists('get_conflict_logs') ? get_conflict_logs(5) : [];
?>

<!-- R30 (T1.5) SIDEBAR LAYOUT — topbar refactor -->
<button class="hamburger" id="hamburger" type="button" aria-label="Menüyü Aç/Kapat"
        onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-backdrop').classList.toggle('open');">
  <i class="fas fa-bars"></i>
</button>
<div class="sidebar-backdrop" id="sidebar-backdrop"
     onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('open');"></div>

<div class="app-shell">
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-head">
      <a href="cyberwebeyeosblacklistadmin.php" class="brand">
        <div class="brand-logo">C</div>
        <div class="brand-text">
          <div class="brand-name">CYBERWEBEYEOS</div>
          <div class="brand-sub">Threat Intel Platform</div>
        </div>
      </a>
    </div>
    <div class="sidebar-search">
      <div class="search-wrap" style="position:relative;">
        <i class="fas fa-search"></i>
        <input type="search" id="global-search" placeholder="Ara…  Ctrl+K">
        <div id="global-search-results" style="display:none;position:absolute;top:calc(100% + 6px);left:0;right:0;background:#fff;border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow-lg);max-height:420px;overflow-y:auto;z-index:200;color:var(--text);"></div>
      </div>
    </div>
    <nav class="topnav" id="topnav">
      <button class="tab-btn active" data-tab="blacklist"><i class="fas fa-shield-alt"></i><span>Blacklist</span></button>
      <button class="tab-btn" data-tab="whitelist"><i class="fas fa-check-circle"></i><span>Whitelist</span><?php if($whitelist_count>0): ?><span class="badge-count" style="background:var(--success);"><?= $whitelist_count ?></span><?php endif; ?></button>
      <button class="tab-btn" data-tab="pending"><i class="fas fa-clock"></i><span>Pending</span><?php if($pending_count>0): ?><span class="badge-count"><?= $pending_count ?></span><?php endif; ?></button>
      <button class="tab-btn" data-tab="lists"><i class="fas fa-layer-group"></i><span>Listeler</span></button>
      <button class="tab-btn" data-tab="usom"><i class="fas fa-globe"></i><span>USOM Feed</span></button>
      <button class="tab-btn" data-tab="catalog"><i class="fas fa-bookmark"></i><span>Feed Kataloğu</span></button>
      <button class="tab-btn" data-tab="users"><i class="fas fa-users-cog"></i><span>Kullanıcılar</span></button>
      <button class="tab-btn" data-tab="dashboard"><i class="fas fa-chart-line"></i><span>Dashboard</span></button>
      <?php
        $__cve_data = @json_decode(@file_get_contents(__DIR__ . '/cve_state.json'), true);
        $__cve_open = 0; $__cve_kev_open = 0;
        foreach (($__cve_data['cves'] ?? []) as $cv) {
            if (empty($cv['dismissed_at'])) {
                $__cve_open++;
                if (!empty($cv['is_kev'])) $__cve_kev_open++;
            }
        }
      ?>
      <button class="tab-btn" data-tab="cve"><i class="fas fa-shield-virus"></i><span>Zafiyet İzleme</span>
        <?php if ($__cve_kev_open > 0): ?><span class="badge-count" style="background:#dc2626;"><?= $__cve_kev_open ?></span>
        <?php elseif ($__cve_open > 0): ?><span class="badge-count" style="background:#f59e0b;"><?= $__cve_open ?></span><?php endif; ?>
      </button>
      <button class="tab-btn" data-tab="status"><i class="fas fa-tachometer-alt"></i><span>Durum &amp; Loglar</span></button>
    </nav>
    <div class="sidebar-foot">
      <div class="user-chip">
        <div class="avatar"><?= strtoupper(substr($current_user, 0, 1)) ?></div>
        <span><?= htmlspecialchars($current_user) ?></span>
        <?php
          $__role = function_exists('cwe_current_role') ? cwe_current_role() : ($_SESSION['cwe_role'] ?? 'viewer');
          $__role_color = ['admin'=>'#dc2626','operator'=>'#f59e0b','viewer'=>'#64748b'][$__role] ?? '#64748b';
        ?>
        <span title="Rolünüz" style="background:<?= $__role_color ?>;color:#fff;padding:2px 8px;border-radius:999px;font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;flex-shrink:0;"><?= htmlspecialchars($__role) ?></span>
        <a href="logout.php" class="logout" title="Çıkış"><i class="fas fa-sign-out-alt"></i></a>
      </div>
    </div>
  </aside>

  <div class="main-pane">

<!-- PENDING STICKY BANNER -->
<?php if ($pending_count > 0): ?>
<div class="pending-banner">
  <div class="pb-text">
    <i class="fas fa-clock" style="color:var(--warning);margin-right:6px;"></i>
    <strong><?= $pending_count ?> onay bekleyen IP</strong> incelemenizi bekliyor.
  </div>
  <button class="btn btn-warning btn-sm" data-jump="pending"><i class="fas fa-arrow-right"></i> İncele</button>
</div>
<?php endif; ?>

<!-- SESSION MESSAGE → TOAST -->
<?php if (isset($_SESSION['message']) && !empty($_SESSION['message'])): ?>
<div class="toast-stack">
  <div class="toast info">
    <i class="fas fa-info-circle" style="color:var(--info);margin-top:2px;"></i>
    <div><?= $_SESSION['message'] ?></div>
    <button class="close" onclick="this.parentElement.remove()">×</button>
  </div>
</div>
<?php unset($_SESSION['message']); endif; ?>

<div class="container">

  <!-- KPI ROW (always visible) -->
  <div class="kpi-row">
    <div class="kpi" data-jump="blacklist">
      <div class="kpi-icon brand"><i class="fas fa-shield-alt"></i></div>
      <div class="kpi-label">Toplam Engellenen</div>
      <div class="kpi-value tabular"><?= number_format($feed_count, 0, ',', '.') ?></div>
      <div class="kpi-delta">Manuel + (USOM ayrı)</div>
    </div>
    <div class="kpi" data-jump="blacklist">
      <div class="kpi-icon info"><i class="fas fa-edit"></i></div>
      <div class="kpi-label">Manuel Kayıt</div>
      <div class="kpi-value tabular"><?= number_format($manual_count, 0, ',', '.') ?></div>
      <div class="kpi-delta">blacklist.txt</div>
    </div>
    <div class="kpi" data-jump="pending">
      <div class="kpi-icon amber"><i class="fas fa-clock"></i></div>
      <div class="kpi-label">Onay Bekleyen</div>
      <div class="kpi-value tabular"><?= $pending_count ?></div>
      <div class="kpi-delta">Pending → review</div>
    </div>
    <div class="kpi" data-jump="whitelist">
      <div class="kpi-icon green"><i class="fas fa-check-circle"></i></div>
      <div class="kpi-label">Whitelist</div>
      <div class="kpi-value tabular"><?= number_format($whitelist_count, 0, ',', '.') ?></div>
      <div class="kpi-delta">Beyaz liste</div>
    </div>
  </div>

  <!-- =================== TAB: BLACKLIST =================== -->
  <div class="tab-panel active" id="tab-blacklist">
<?php
// R90: v2 cerrahi port — sadece tab-blacklist içeriği v2 sade UI ile değiştirildi.
// PHP helper'lar (cwe_msg_escape, _cwe_cached_count, __ln_count) global hoisting
// için top-level scope'ta korundu — diğer modüller bunlara güveniyor.

// Resolve active list kind from lists.json by $list_filter slug.
$__active_kind = 'manual';
$__active_list_name = '';
if (isset($list_filter)) {
    if ($list_filter === 'all' || $list_filter === 'Manuel') {
        $__active_kind = 'system';
        $__active_list_name = 'Tümü Manuel';
    } elseif ($list_filter === 'all-external') {
        $__active_kind = 'external';
        $__active_list_name = 'Tümü Dış Kaynak';
    } else {
        $__lj_path = __DIR__ . '/lists.json';
        if (file_exists($__lj_path)) {
            foreach (json_decode(file_get_contents($__lj_path), true)['lists'] ?? [] as $__l) {
                if (($__l['slug'] ?? '') === $list_filter || ($__l['id'] ?? '') === $list_filter) {
                    $__active_kind = $__l['kind'] ?? 'manual';
                    $__active_list_name = $__l['name'] ?? $list_filter;
                    break;
                }
            }
        }
    }
}
$__aside_hidden = in_array($__active_kind, ['external', 'dynamic'], true);

// Sidebar list navigation — 3-section grouping
$__sidebar_lists = file_exists(__DIR__ . '/lists.json')
    ? (json_decode(file_get_contents(__DIR__ . '/lists.json'), true)['lists'] ?? [])
    : [];
$__by_kind_bl = ['system' => [], 'manual' => [], 'external' => [], 'dynamic' => []];
foreach ($__sidebar_lists as $__l) {
    if (($__l['side'] ?? 'blacklist') !== 'blacklist') continue;
    if (empty($__l['enabled']) && empty($__l['system'])) continue;
    $__kind = $__l['kind'] ?? 'manual';
    if (isset($__by_kind_bl[$__kind])) $__by_kind_bl[$__kind][] = $__l;
}

/**
 * HTML-escape user-supplied content for inclusion in $_SESSION['message']
 * or any HTML output. Always use this before concatenating untrusted input.
 */
function cwe_msg_escape(string $text): string {
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

/**
 * Cached line count with mtime-based invalidation (R86-perf).
 * Cache: /tmp/cwe_cnt/<basename>.json — {"mtime": int, "count": int}
 */
function _cwe_cached_count(string $file_path): int {
    if (!is_file($file_path)) return 0;
    $cache_dir = sys_get_temp_dir() . '/cwe_cnt';
    if (!is_dir($cache_dir)) { @mkdir($cache_dir, 0777, true); @chmod($cache_dir, 0777); }
    $basename = basename($file_path);
    $cache_file = $cache_dir . '/' . $basename . '.json';
    $current_mtime = filemtime($file_path);
    if (is_file($cache_file)) {
        $cached = @json_decode(@file_get_contents($cache_file), true);
        if (is_array($cached) && ($cached['mtime'] ?? null) === $current_mtime) {
            return (int)($cached['count'] ?? 0);
        }
    }
    $count = 0;
    $fh = @fopen($file_path, 'r');
    if ($fh) {
        while (($line = fgets($fh)) !== false) {
            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#') continue;
            $count++;
        }
        fclose($fh);
    }
    if (@file_put_contents($cache_file, json_encode(['mtime' => $current_mtime, 'count' => $count]), LOCK_EX) === false) {
        static $logged_once = false;
        if (!$logged_once) { error_log("[R86-perf] cache write failed for $cache_file (check $cache_dir ownership)"); $logged_once = true; }
    }
    return $count;
}

function __ln_count($l) {
    $f = is_array($l) ? ($l['file'] ?? '') : (string)$l;
    return $f ? _cwe_cached_count($f) : 0;
}

// R90 v2: sidebar item renderer — sade, inline action button yok
function __bl_v2_item($l) {
    $slug = htmlspecialchars($l['slug'] ?? $l['id'] ?? '');
    $name = htmlspecialchars($l['name'] ?? '');
    $cnt = __ln_count($l);
    $is_active = isset($GLOBALS['list_filter']) && ($GLOBALS['list_filter'] === ($l['slug'] ?? '') || $GLOBALS['list_filter'] === ($l['id'] ?? ''));
    echo '<li' . ($is_active ? ' class="active"' : '') . '>';
    echo '<a href="?list=' . $slug . '" data-bl-list="' . $slug . '">';
    echo '<span>' . $name . '</span>';
    echo '<span class="bl-count">' . number_format($cnt, 0, ',', '.') . '</span>';
    echo '</a></li>';
}

// KPI rakamları
$__bl_kpi_total    = $feed_count ?? _cwe_cached_count(__DIR__ . '/cyberwebeyeosblacklist.txt');
$__bl_kpi_manuel   = $manual_count ?? _cwe_cached_count(__DIR__ . '/blacklist.txt');
$__bl_kpi_external = 0;
foreach ($__by_kind_bl['external'] as $__l) { $__bl_kpi_external += __ln_count($__l); }
$__bl_kpi_feeds    = count($__by_kind_bl['external']);

// Aktif liste başlık
$__bl_active_title = 'Kara Liste — Tüm Manuel Kayıtlar';
$__bl_active_kind_label = 'Manuel (Sistem)';
$__bl_active_kind_class = 'bl-kind-system';
if (($list_filter ?? 'all') === 'all-external') {
    $__bl_active_title = 'Tüm Dış Kaynaklar';
    $__bl_active_kind_label = 'Özet';
    $__bl_active_kind_class = 'bl-kind-external';
} elseif (($list_filter ?? 'all') !== 'all' && ($list_filter ?? '') !== 'Manuel') {
    if ($__active_list_name !== '') $__bl_active_title = $__active_list_name;
    $__bl_active_kind_label = match($__active_kind) {
        'system'   => 'Manuel (Sistem)',
        'manual'   => 'Manuel',
        'external' => 'Dış Kaynak',
        'dynamic'  => 'Akıllı Liste',
        default    => $__active_kind,
    };
    $__bl_active_kind_class = 'bl-kind-' . htmlspecialchars($__active_kind);
}
?>
    <div class="bl-app" data-active-kind="<?= htmlspecialchars($__active_kind) ?>">
      <!-- R90 v2: 3-section sidebar list picker -->
      <nav class="bl-listnav" aria-label="Liste seçimi">
        <div class="bl-section">
          <h3>Manuel Listeler <span class="bl-section-count"><?= count($__by_kind_bl['system']) + count($__by_kind_bl['manual']) ?></span></h3>
          <ul>
            <li class="<?= (($list_filter ?? 'all') === 'all' || ($list_filter ?? '') === 'Manuel') ? 'active' : '' ?>">
              <a href="cyberwebeyeosblacklistadmin.php" data-bl-list="all">
                <span>Tümü Manuel</span>
                <span class="bl-count"><?php
                  $__tot = 0;
                  foreach (array_merge($__by_kind_bl['system'], $__by_kind_bl['manual']) as $__l) $__tot += __ln_count($__l);
                  echo number_format($__tot, 0, ',', '.');
                ?></span>
              </a>
            </li>
            <?php foreach ($__by_kind_bl['system'] as $__l) __bl_v2_item($__l); ?>
            <?php foreach ($__by_kind_bl['manual'] as $__l) __bl_v2_item($__l); ?>
          </ul>
        </div>
        <div class="bl-section">
          <h3>Dış Kaynaklar <span class="bl-section-count"><?= count($__by_kind_bl['external']) ?></span></h3>
          <ul>
            <li class="<?= (($list_filter ?? '') === 'all-external') ? 'active' : '' ?>">
              <a href="?list=all-external" data-bl-list="all-external">
                <span>Tümü Dış Kaynak</span>
                <span class="bl-count"><?= count($__by_kind_bl['external']) ?> kaynak</span>
              </a>
            </li>
            <?php foreach ($__by_kind_bl['external'] as $__l) __bl_v2_item($__l); ?>
            <?php if (empty($__by_kind_bl['external'])): ?>
            <li class="bl-empty">Henüz dış kaynak yok</li>
            <?php endif; ?>
          </ul>
        </div>
        <div class="bl-section">
          <h3>Akıllı Listeler <span class="bl-section-count"><?= count($__by_kind_bl['dynamic']) ?></span></h3>
          <ul>
            <?php foreach ($__by_kind_bl['dynamic'] as $__l) __bl_v2_item($__l); ?>
            <?php if (empty($__by_kind_bl['dynamic'])): ?>
            <li class="bl-empty">Yakında — Sprint 9</li>
            <?php endif; ?>
          </ul>
        </div>
      </nav>

      <main class="bl-main">
        <!-- R90 v2: 4 KPI cards (blacklist-specific: total + manual + external + feeds) -->
        <section class="bl-kpi" aria-label="Blacklist özet sayılar">
          <div class="bl-kpi-card alt">
            <span class="bl-kpi-lbl">Toplam Engellenen</span>
            <span class="bl-kpi-val"><?= number_format($__bl_kpi_total, 0, ',', '.') ?></span>
          </div>
          <div class="bl-kpi-card">
            <span class="bl-kpi-lbl">Manuel Kayıt</span>
            <span class="bl-kpi-val"><?= number_format($__bl_kpi_manuel, 0, ',', '.') ?></span>
          </div>
          <div class="bl-kpi-card">
            <span class="bl-kpi-lbl">Dış Kaynak Toplamı</span>
            <span class="bl-kpi-val"><?= number_format($__bl_kpi_external, 0, ',', '.') ?></span>
          </div>
          <div class="bl-kpi-card">
            <span class="bl-kpi-lbl">Aktif Feed Sayısı</span>
            <span class="bl-kpi-val"><?= number_format($__bl_kpi_feeds, 0, ',', '.') ?></span>
          </div>
        </section>

<!-- R88b: Fragment modunda buffer'a alınan outer layout burada atılır — sadece #bl-content içeriği response gövdesine yazılır. -->
<?php if ($__is_fragment) { @ob_end_clean(); } ?>
<!-- R89b: vanilla fetch swap target — fragment mode'da wrapper YOK -->
<?php if (!$__is_fragment): ?><section id="bl-content"><?php endif; ?>
          <header class="bl-card-head">
            <h2>
              <?= htmlspecialchars($__bl_active_title) ?>
              <span class="bl-kind-tag <?= $__bl_active_kind_class ?>"><?= htmlspecialchars($__bl_active_kind_label) ?></span>
            </h2>
            <div class="bl-card-actions">
              <form method="post" style="display:inline;">
                <button type="submit" name="sync_blacklist" class="btn btn-ghost btn-sm" title="Manuel listeyi birleşik feed'e senkronize et">
                  <i class="fas fa-sync"></i> Senkronize Et
                </button>
              </form>
              <a href="cyberwebeyeosblacklist.txt" target="_blank" class="btn btn-ghost btn-sm" title="Firewall feed (TXT)">
                <i class="fas fa-file-alt"></i> Feed.txt
              </a>
            </div>
          </header>

          <?php if ($__aside_hidden): ?>
          <div class="bl-banner">
            <?php if ($__active_kind === 'external'): ?>
              <i class="fas fa-globe" style="margin-right:6px;"></i>
              Bu liste <strong>dış kaynak</strong> — cron otomatik günceller.
              Manuel ekleme için <a href="cyberwebeyeosblacklistadmin.php">Tümü Manuel</a> listesini kullanın.
            <?php else: ?>
              <i class="fas fa-filter" style="margin-right:6px;"></i>
              Bu <strong>akıllı liste</strong> kaydedilmiş filtreden türetilir — manuel ekleme yapılamaz.
            <?php endif; ?>
          </div>
          <?php else: ?>
          <!-- R90 v2: inline manuel ekleme (drawer overlay yerine native <details> disclosure) -->
          <section class="bl-add-form">
            <details>
              <summary>Manuel Ekleme — IP / CIDR / Domain / URL (her satır bir kayıt)</summary>
              <form method="post" action="<?= htmlspecialchars($_SERVER["PHP_SELF"]) ?>" class="bl-add-form-body" id="manual-add-form">
                <textarea name="ip_address" rows="4" required
                  placeholder="192.0.2.1&#10;malware.example.com&#10;https://phish.example.org/login&#10;10.0.0.0/24"></textarea>
                <input type="text" name="comment" placeholder="Yorum / açıklama (opsiyonel — örn: phishing, c2, ransomware)">
                <input type="hidden" name="target_list" value="<?= htmlspecialchars($list_filter ?? 'all') ?>">
                <input type="hidden" name="confidence" value="75">
                <input type="hidden" name="valid_until_preset" value="+90 days">
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
                  <button type="submit" class="btn btn-primary btn-sm">
                    <i class="fas fa-plus"></i> Ekle
                  </button>
                  <span class="bl-add-help">Otomatik tip tespiti · güven=75 · 90 gün geçerli</span>
                </div>
              </form>
            </details>
          </section>
          <?php endif; ?>

          <?php display_blacklist($search_ip, $per_page, $page, $list_filter); ?>
<?php if (!$__is_fragment): ?></section><!-- /#bl-content -->
<?php endif; ?>
<?php
if ($__is_fragment) {
    // R88b: fragment mode — sadece #bl-content içeriği döndürüldü, dış katmanları boğ
    exit;
}
?>
      </main>
    </div>
  </div>

  <!-- =================== TAB: WHITELIST =================== -->
  <div class="tab-panel" id="tab-whitelist">
    <div class="main-grid">
      <section>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon green"><i class="fas fa-check-circle"></i></span> Beyaz Liste (Whitelist)</h2>
            <div class="card-actions">
              <span class="badge badge-whitelist tabular"><?= $whitelist_count ?> kayıt</span>
            </div>
          </div>
          <div class="card-body flush">
            <?php if (count($whitelist_items) === 0): ?>
              <div class="empty">
                <div class="empty-icon muted"><i class="fas fa-shield-alt"></i></div>
                <div class="empty-title">Whitelist boş</div>
                <div class="empty-desc">Sağdaki form ile IP / CIDR ekleyebilirsin.</div>
              </div>
            <?php else: ?>
              <div class="table-responsive">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>IP / CIDR</th>
                      <th>Tür</th>
                      <th>Tarih / Saat</th>
                      <th>Ekleyen</th>
                      <th>Yorum</th>
                      <th style="text-align:right;">İşlem</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($whitelist_items as $wl): $entry = is_array($wl) ? $wl['entry'] : $wl; ?>
                    <tr>
                      <td class="mono"><i class="fas fa-network-wired" style="color:var(--text-muted);margin-right:6px;"></i><?= htmlspecialchars($entry) ?></td>
                      <td><span class="badge badge-whitelist"><?= strpos($entry, '/') !== false ? 'CIDR' : 'IP' ?></span></td>
                      <td style="font-size:11.5px;color:var(--text-muted);" class="mono"><?= htmlspecialchars($wl['date'] ?? '-') ?></td>
                      <td><?php if (!empty($wl['user'])): ?><span class="badge badge-manual"><?= htmlspecialchars($wl['user']) ?></span><?php else: ?><span style="color:var(--text-muted);">-</span><?php endif; ?></td>
                      <td style="font-size:12px;color:var(--text-muted);"><?= htmlspecialchars($wl['comment'] ?? '') ?></td>
                      <td style="text-align:right;">
                        <form method="post" action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" style="display:inline;">
                          <input type="hidden" name="wl_delete" value="<?= htmlspecialchars($entry) ?>">
                          <button type="submit" class="btn-delete" onclick="return confirm('Silinsin mi?')"><i class="fas fa-trash"></i></button>
                        </form>
                      </td>
                    </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php endif; ?>
          </div>
        </div>
      </section>

      <aside>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon green"><i class="fas fa-plus"></i></span> Whitelist'e Ekle</h2>
          </div>
          <div class="card-body">
            <form method="post" action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>">
              <div class="field">
                <label>IP veya CIDR</label>
                <input type="text" name="wl_add" placeholder="203.0.113.1 veya 203.0.113.0/24" required>
                <div class="field-help">Whitelist'teki IP'ler blacklist'e eklenemez</div>
              </div>
              <div class="field">
                <label>Yorum / Sebep</label>
                <input type="text" name="wl_comment" placeholder="örn: ofis IP, kritik servis, prod NAT">
                <div class="field-help">Bu IP'nin neden whitelist'te olduğu (audit için)</div>
              </div>
              <button type="submit" class="btn btn-success btn-block">
                <i class="fas fa-plus"></i> Whitelist'e Ekle
              </button>
            </form>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon slate"><i class="fas fa-info-circle"></i></span> Bilgi</h2>
          </div>
          <div class="card-body" style="font-size:12.5px;color:var(--text-muted);line-height:1.65;">
            Whitelist, blacklist'e <strong>asla</strong> eklenmemesi gereken güvenli IP/CIDR'leri tutar.
            Manuel veya otomatik kaynaklar bu listedeki kayıtları engellemez.
          </div>
        </div>
      </aside>
    </div>
  </div>

  <!-- =================== TAB: PENDING =================== -->
  <div class="tab-panel" id="tab-pending">
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon amber"><i class="fas fa-clock"></i></span> Onay Bekleyen IP'ler
          <?php if ($pending_count > 0): ?>
            <span class="badge badge-pending" style="margin-left:6px;"><?= $pending_count ?></span>
          <?php endif; ?>
        </h2>
        <div class="card-actions">
          <a href="move_to_pending.php" class="btn btn-ghost btn-sm">
            <i class="fas fa-exchange-alt"></i> Pending'e Taşı (manuel)
          </a>
        </div>
      </div>
      <div class="card-body flush">
        <?php if ($pending_count > 0): ?>
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th>IP / Domain</th>
                  <th>Kaynak</th>
                  <th>Tespit Tarihi</th>
                  <th style="text-align:right;">İşlem</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($pending_list as $p): ?>
                <tr>
                  <td class="mono"><i class="fas fa-network-wired" style="color:var(--text-muted);margin-right:6px;"></i><?= htmlspecialchars($p['ip']) ?></td>
                  <td><span class="badge badge-manual"><?= htmlspecialchars(ucfirst($p['source'] ?: 'manuel')) ?></span></td>
                  <td style="color:var(--text-muted);"><?= htmlspecialchars($p['created_at'] ?? '-') ?></td>
                  <td style="text-align:right;white-space:nowrap;">
                    <a href="approve_ip.php?token=<?= htmlspecialchars($p['id']) ?>" class="btn btn-success btn-sm">
                      <i class="fas fa-check"></i> İncele &amp; Karar Ver
                    </a>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php else: ?>
          <div class="empty">
            <div class="empty-icon"><i class="fas fa-check-circle"></i></div>
            <div class="empty-title">Onay bekleyen IP yok</div>
            <div class="empty-desc">Tüm pending kayıtlar işlenmiş.</div>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <!-- =================== TAB: USOM (INLINE NATIVE) =================== -->
  <?php
  // USOM verisi
  $usom_full = $usom_state['file_entries'] ?? 0;
  $usom_schedule_data = @json_decode(@file_get_contents('/var/www/html/usom/usom-schedule.json'), true) ?? [];
  $usom_full_sch = $usom_schedule_data['full'] ?? ['enabled'=>true,'type'=>'monthly','day_of_month'=>1,'day_of_week'=>0,'hour'=>1,'minute'=>0];
  $usom_inc_sch  = $usom_schedule_data['incremental'] ?? ['enabled'=>true,'days'=>[0,1,2,3,4,5,6],'hours'=>[7,13,19],'minute'=>0];
  $usom_day_names = ['Paz','Pzt','Sal','Çar','Per','Cum','Cmt'];
  $usom_feeds = [
    ['file'=>'url-list.txt',     'label'=>'Birleşik Liste','sub'=>'Domain + IP + URL + IPv6','color'=>'#6366f1'],
    ['file'=>'domain-list.txt',  'label'=>'Domain',        'sub'=>'Zararlı alan adları',     'color'=>'#0ea5e9'],
    ['file'=>'ip-list.txt',      'label'=>'IPv4',          'sub'=>'Zararlı IPv4 adresleri', 'color'=>'#10b981'],
    ['file'=>'url-only-list.txt','label'=>'URL',           'sub'=>'Zararlı URL\'ler',       'color'=>'#f59e0b'],
    ['file'=>'ip6-list.txt',     'label'=>'IPv6',          'sub'=>'Zararlı IPv6 adresleri', 'color'=>'#8b5cf6'],
    ['file'=>'ip6net-list.txt',  'label'=>'IPv6 Subnet',   'sub'=>'Zararlı IPv6 subnetler', 'color'=>'#ec4899'],
  ];
  $usom_base = '/blacklist/usom';
  foreach ($usom_feeds as &$_f) {
    $p = '/var/www/html/usom/' . $_f['file'];
    $_f['count'] = 0;
    if (file_exists($p)) {
      $fh = @fopen($p, 'r');
      if ($fh) {
        while (($line = fgets($fh)) !== false) {
          if (preg_match('/^# Toplam kayıt: (\d+)/', $line, $m)) { $_f['count'] = (int)$m[1]; break; }
        }
        fclose($fh);
      }
      $b = filesize($p);
      $_f['size'] = $b >= 1048576 ? round($b/1048576,1).' MB' : ($b >= 1024 ? round($b/1024).' KB' : $b.' B');
    } else { $_f['size'] = '-'; }
    $_f['url'] = $usom_base . '/' . $_f['file'];
  }
  unset($_f);
  ?>
  <div class="tab-panel" id="tab-usom">
    <!-- USOM Status Strip -->
    <div class="kpi-row">
      <div class="kpi">
        <div class="kpi-icon info"><i class="fas fa-database"></i></div>
        <div class="kpi-label">USOM Toplam</div>
        <div class="kpi-value tabular"><?= number_format($usom_full, 0, ',', '.') ?></div>
        <div class="kpi-delta">API'den çekilen kayıt</div>
      </div>
      <div class="kpi">
        <div class="kpi-icon brand"><i class="fas fa-sync"></i></div>
        <div class="kpi-label">Son Sync</div>
        <div class="kpi-value" style="font-size:15px;line-height:1.3;"><?= htmlspecialchars(substr($usom_last_sync, 0, 19)) ?></div>
        <div class="kpi-delta"><?= $usom_type === 'full' ? '<span class="badge badge-usom">Tam</span>' : ($usom_type === 'incremental' ? '<span class="badge badge-manual">Artımlı</span>' : '-') ?></div>
      </div>
      <div class="kpi">
        <div class="kpi-icon amber"><i class="fas fa-clock"></i></div>
        <div class="kpi-label">Tam Sync (Aylık)</div>
        <div class="kpi-value" style="font-size:15px;line-height:1.3;">
          <?php
            $t = $usom_full_sch;
            if (!empty($t['enabled'])) {
              echo $t['type']==='weekly' ? $usom_day_names[(int)$t['day_of_week']] : 'Her ayın '.((int)$t['day_of_month']).'\'i';
              echo ' · '.sprintf('%02d:%02d', (int)$t['hour'], (int)$t['minute']);
            } else { echo 'Devre dışı'; }
          ?>
        </div>
        <div class="kpi-delta"><?= !empty($t['enabled']) ? 'Aktif' : 'Kapalı' ?></div>
      </div>
      <div class="kpi">
        <div class="kpi-icon green"><i class="fas fa-bolt"></i></div>
        <div class="kpi-label">Artımlı (Günlük)</div>
        <div class="kpi-value" style="font-size:15px;line-height:1.3;">
          <?php
            $i = $usom_inc_sch;
            if (!empty($i['enabled'])) {
              echo count($i['hours'] ?? []).' kez/gün';
              echo ' · '.implode(',', array_map(fn($h)=>sprintf('%02d',$h), $i['hours'] ?? []));
            } else { echo 'Devre dışı'; }
          ?>
        </div>
        <div class="kpi-delta"><?= !empty($i['enabled']) ? count($i['days'] ?? []).' gün/hafta' : 'Kapalı' ?></div>
      </div>
    </div>

    <!-- USOM Feed Cards -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon info"><i class="fas fa-stream"></i></span> USOM Feed Dosyaları</h2>
        <div class="card-actions">
          <button class="btn btn-warning btn-sm" id="usom-run-full"><i class="fas fa-rotate-right"></i> Şimdi Tam Sync</button>
          <button class="btn btn-success btn-sm" id="usom-run-inc"><i class="fas fa-bolt"></i> Şimdi Artımlı</button>
        </div>
      </div>
      <div class="card-body">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;">
          <?php foreach ($usom_feeds as $f): ?>
          <div style="border:1px solid var(--border);border-radius:10px;padding:16px;background:#fff;">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
              <span style="width:10px;height:10px;border-radius:50%;background:<?= $f['color'] ?>;flex-shrink:0;"></span>
              <div>
                <div style="font-weight:600;font-size:14px;"><?= htmlspecialchars($f['label']) ?></div>
                <div style="font-size:11.5px;color:var(--text-muted);"><?= htmlspecialchars($f['sub']) ?></div>
              </div>
            </div>
            <?php if ($f['count'] > 0): ?>
            <div style="display:flex;gap:14px;padding:8px 0;border-top:1px solid var(--slate-100);font-size:12px;color:var(--text-muted);">
              <span><strong style="color:var(--text);" class="tabular"><?= number_format($f['count'], 0, ',', '.') ?></strong> kayıt</span>
              <span><strong style="color:var(--text);"><?= $f['size'] ?></strong></span>
            </div>
            <?php endif; ?>
            <input type="text" readonly value="<?= htmlspecialchars($f['url']) ?>" class="form-control" style="font-size:11px;font-family:'Fira Code',monospace;margin:8px 0;cursor:pointer;" onclick="this.select();navigator.clipboard?.writeText(this.value);this.style.borderColor='var(--success)';setTimeout(()=>this.style.borderColor='',1200);" title="Kopyalamak için tıkla">
            <div style="display:flex;gap:6px;">
              <a href="<?= htmlspecialchars($f['url']) ?>" target="_blank" class="btn btn-primary btn-sm" style="flex:1;justify-content:center;"><i class="fas fa-eye"></i> Görüntüle</a>
              <a href="<?= htmlspecialchars($f['url']) ?>" download class="btn btn-ghost btn-sm" style="flex:1;justify-content:center;"><i class="fas fa-download"></i> İndir</a>
            </div>
          </div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>

    <!-- USOM Schedule Editor -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon brand"><i class="fas fa-calendar-alt"></i></span> Zamanlama Ayarları</h2>
        <div class="card-actions">
          <button class="btn btn-primary btn-sm" id="usom-save-sch"><i class="fas fa-save"></i> Kaydet</button>
        </div>
      </div>
      <div class="card-body">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">
          <!-- Full Sync -->
          <div>
            <h3 style="font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;margin-bottom:12px;">
              Tam Sync
              <label style="display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:400;color:var(--text-muted);">
                <input type="checkbox" id="usom-full-enabled" <?= !empty($usom_full_sch['enabled']) ? 'checked' : '' ?>>
                Aktif
              </label>
            </h3>
            <div class="field">
              <label>Periyot</label>
              <select id="usom-full-type">
                <option value="monthly" <?= ($usom_full_sch['type'] ?? '')==='monthly' ? 'selected' : '' ?>>Aylık</option>
                <option value="weekly" <?= ($usom_full_sch['type'] ?? '')==='weekly' ? 'selected' : '' ?>>Haftalık</option>
              </select>
            </div>
            <div class="field" id="usom-full-dom-field">
              <label>Ayın günü</label>
              <select id="usom-full-dom">
                <?php for($d=1;$d<=28;$d++): ?>
                  <option value="<?= $d ?>" <?= ((int)($usom_full_sch['day_of_month'] ?? 1))===$d ? 'selected' : '' ?>><?= $d ?></option>
                <?php endfor; ?>
              </select>
            </div>
            <div class="field" id="usom-full-dow-field" style="display:none;">
              <label>Hafta günü</label>
              <select id="usom-full-dow">
                <?php $dayLongs = ['Pazar','Pazartesi','Salı','Çarşamba','Perşembe','Cuma','Cumartesi'];
                foreach ($dayLongs as $i=>$n): ?>
                  <option value="<?= $i ?>" <?= ((int)($usom_full_sch['day_of_week'] ?? 0))===$i ? 'selected' : '' ?>><?= $n ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="field">
              <label>Saat</label>
              <input type="time" id="usom-full-time" value="<?= sprintf('%02d:%02d', (int)($usom_full_sch['hour'] ?? 1), (int)($usom_full_sch['minute'] ?? 0)) ?>">
            </div>
          </div>

          <!-- Incremental Sync -->
          <div>
            <h3 style="font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;margin-bottom:12px;">
              Artımlı Sync
              <label style="display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:400;color:var(--text-muted);">
                <input type="checkbox" id="usom-inc-enabled" <?= !empty($usom_inc_sch['enabled']) ? 'checked' : '' ?>>
                Aktif
              </label>
            </h3>
            <div class="field">
              <label>Günler</label>
              <div id="usom-inc-days" style="display:flex;flex-wrap:wrap;gap:4px;">
                <?php foreach ($usom_day_names as $i=>$n):
                  $on = in_array($i, array_map('intval', $usom_inc_sch['days'] ?? []), true); ?>
                  <span class="badge <?= $on ? 'badge-manual' : 'badge-source' ?>" data-day="<?= $i ?>" style="cursor:pointer;user-select:none;padding:4px 10px;<?= $on?'border:1px solid var(--brand-500);':'' ?>"><?= $n ?></span>
                <?php endforeach; ?>
              </div>
            </div>
            <div class="field">
              <label>Saatler</label>
              <div id="usom-inc-hours" style="display:flex;flex-wrap:wrap;gap:3px;">
                <?php for($h=0;$h<24;$h++):
                  $on = in_array($h, array_map('intval', $usom_inc_sch['hours'] ?? []), true); ?>
                  <span class="badge <?= $on ? 'badge-manual' : 'badge-source' ?>" data-hour="<?= $h ?>" style="cursor:pointer;user-select:none;font-family:'Fira Code',monospace;padding:3px 7px;<?= $on?'border:1px solid var(--brand-500);':'' ?>"><?= sprintf('%02d', $h) ?></span>
                <?php endfor; ?>
              </div>
            </div>
            <div class="field" style="display:flex;align-items:center;gap:10px;">
              <label style="margin:0;">Dakika</label>
              <input type="number" id="usom-inc-minute" min="0" max="59" value="<?= (int)($usom_inc_sch['minute'] ?? 0) ?>" style="width:80px;">
            </div>
          </div>
        </div>
        <div id="usom-sch-msg" style="margin-top:16px;font-size:13px;display:none;"></div>
      </div>
    </div>
  </div>

  <!-- =================== TAB: FEED KATALOĞU (INLINE NATIVE) =================== -->
  <?php
  $srcs_config = @json_decode(@file_get_contents(__DIR__ . '/sources_config.json'), true) ?? ['sources'=>[],'settings'=>[]];
  $configured_sources = $srcs_config['sources'] ?? [];
  $settings_data = $srcs_config['settings'] ?? [];

  // Crontab durumu (cyberwebeyeos için)
  $crontab_active = false;
  $crontab_lines = @shell_exec('crontab -u www-data -l 2>/dev/null') ?? '';
  if (strpos($crontab_lines, 'usom-dispatcher') !== false || strpos($crontab_lines, 'cyberwebeyeos') !== false) {
    $crontab_active = true;
  }
  ?>
  <div class="tab-panel" id="tab-catalog">

    <!-- Configured Sources (active) -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon info"><i class="fas fa-bookmark"></i></span> Yapılandırılmış Kaynaklar</h2>
        <div class="card-actions">
          <span class="badge badge-source"><?= count($configured_sources) ?> kaynak</span>
          <span class="badge <?= $crontab_active ? 'badge-whitelist' : 'badge-pending' ?>" title="Cron durumu">
            <i class="fas fa-clock"></i> Crontab: <?= $crontab_active ? 'Aktif' : 'Pasif' ?>
          </span>
          <form method="post" action="sources_manager.php" style="display:inline;">
            <button type="submit" name="update_all" class="btn btn-primary btn-sm" title="Tüm kaynakları şimdi çek">
              <i class="fas fa-sync"></i> Tümünü Çek
            </button>
          </form>
        </div>
      </div>
      <div class="card-body flush">
        <?php if (empty($configured_sources)): ?>
          <div class="empty">
            <div class="empty-icon muted"><i class="fas fa-folder-open"></i></div>
            <div class="empty-title">Yapılandırılmış kaynak yok</div>
            <div class="empty-desc">Aşağıdan yeni kaynak ekleyebilir veya "Tavsiye Edilen" tablosundan seçebilirsin.</div>
          </div>
        <?php else: ?>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Kaynak Adı</th>
                <th>URL</th>
                <th>Tip</th>
                <th>Süre</th>
                <th title="R35 (T2.5): kaynak güvenilirlik skoru">Güven</th>
                <th class="tabular">Kayıt</th>
                <th>Son Güncelleme</th>
                <th>Durum</th>
                <th style="text-align:right;">İşlem</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($configured_sources as $s):
                $interval_label = (int)($s['update_interval'] ?? 3600) >= 3600
                  ? round((int)($s['update_interval'] ?? 3600) / 3600) . 'h'
                  : round((int)($s['update_interval'] ?? 3600) / 60) . 'm';

                // GERÇEK durum tespiti (config'in last_status'ına güvenme — dosyaya bak)
                $out = $s['output_file'] ?? '';
                $file_exists = $out && file_exists($out);
                $file_size = $file_exists ? filesize($out) : 0;
                $file_mtime = $file_exists ? filemtime($out) : 0;
                $age_seconds = $file_mtime ? time() - $file_mtime : 0;
                $age_hours = $age_seconds > 0 ? round($age_seconds / 3600, 1) : 0;

                if (!empty($s['enabled']) && $file_exists && $file_size > 0 && $age_hours < 24) {
                  $real_status = ['badge'=>'badge-whitelist','icon'=>'check','label'=>'Çalışıyor','tip'=>"Dosya: {$file_size}B, {$age_hours}h önce"];
                } elseif (!empty($s['enabled']) && $file_exists && $file_size > 0) {
                  $real_status = ['badge'=>'badge-pending','icon'=>'clock','label'=>"Eski ({$age_hours}h)",'tip'=>"Dosya eski, fetch gerek"];
                } elseif (!empty($s['enabled'])) {
                  $real_status = ['badge'=>'badge-pending','icon'=>'exclamation-triangle','label'=>'Dosya YOK','tip'=>"Aktif ama henüz fetch edilmemiş — 'Şimdi Çek' bas"];
                } else {
                  $real_status = ['badge'=>'badge-source','icon'=>'pause','label'=>'Pasif','tip'=>"Toggle ile aktif et"];
                }
                // Gerçek kayıt sayısı = dosya satır sayısı (yorum harici); yoksa config değeri
                $real_count = $file_exists ? _cwe_cached_count($out) : (int)($s['entry_count'] ?? 0);
              ?>
              <tr>
                <td><strong style="color:var(--text);"><?= htmlspecialchars($s['name'] ?? '-') ?></strong>
                    <?php if (!empty($s['description'])): ?><br><span style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($s['description']) ?></span><?php endif; ?>
                </td>
                <td><a href="<?= htmlspecialchars($s['url'] ?? '#') ?>" target="_blank" rel="noopener" class="mono" style="font-size:11.5px;color:var(--text-muted);word-break:break-all;"><?= htmlspecialchars($s['url'] ?? '-') ?></a></td>
                <td><span class="badge badge-source"><?= htmlspecialchars($s['type'] ?? '-') ?></span></td>
                <td class="mono" style="font-size:12px;"><?= htmlspecialchars($interval_label) ?></td>
                <?php
                  // R35 (T2.5): default_confidence badge (yoksa 60 default)
                  $__src_conf = isset($s['default_confidence']) ? (int)$s['default_confidence'] : 60;
                  $__src_conf_color = cwe_confidence_color($__src_conf);
                ?>
                <td>
                  <span title="Default güven skoru — bu kaynaktan gelen IoC'lere atanır" style="display:inline-flex;align-items:center;gap:4px;font-family:'Fira Code',monospace;font-size:11.5px;color:<?= $__src_conf_color ?>;font-weight:700;">
                    <span style="width:6px;height:6px;border-radius:50%;background:<?= $__src_conf_color ?>;"></span><?= $__src_conf ?>
                  </span>
                </td>
                <td class="tabular mono" style="font-size:12px;"><?= number_format($real_count, 0, ',', '.') ?></td>
                <td style="font-size:11.5px;color:var(--text-muted);">
                  <?= htmlspecialchars($s['last_update'] ?? '-') ?>
                  <?php if ($file_exists): ?><br><span style="font-size:10px;color:var(--success);">dosya: <?= round($file_size/1024,1) ?>KB</span><?php endif; ?>
                </td>
                <td>
                  <span class="badge <?= $real_status['badge'] ?>" title="<?= htmlspecialchars($real_status['tip']) ?>">
                    <i class="fas fa-<?= $real_status['icon'] ?>"></i> <?= htmlspecialchars($real_status['label']) ?>
                  </span>
                </td>
                <td style="text-align:right;white-space:nowrap;">
                  <form method="post" action="sources_manager.php" style="display:inline;">
                    <input type="hidden" name="update_source" value="1">
                    <input type="hidden" name="source_id" value="<?= htmlspecialchars($s['id'] ?? '') ?>">
                    <input type="hidden" name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=catalog">
                    <button type="submit" class="btn btn-success btn-sm" title="Şimdi çek (HTTP'den indir)" style="background:var(--brand-700);">
                      <i class="fas fa-cloud-download-alt"></i>
                    </button>
                  </form>
                  <form method="post" action="sources_manager.php" style="display:inline;">
                    <input type="hidden" name="toggle_source" value="1">
                    <input type="hidden" name="source_id" value="<?= htmlspecialchars($s['id'] ?? '') ?>">
                    <input type="hidden" name="enabled" value="<?= !empty($s['enabled']) ? '0' : '1' ?>">
                    <input type="hidden" name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=catalog">
                    <button type="submit" class="btn btn-ghost btn-sm" title="<?= !empty($s['enabled']) ? 'Pasif yap' : 'Aktif yap' ?>">
                      <i class="fas fa-<?= !empty($s['enabled']) ? 'pause' : 'play' ?>"></i>
                    </button>
                  </form>
                  <form method="post" action="sources_manager.php" style="display:inline;" onsubmit="return confirm('Bu kaynak silinsin mi?');">
                    <input type="hidden" name="delete_source" value="1">
                    <input type="hidden" name="source_id" value="<?= htmlspecialchars($s['id'] ?? '') ?>">
                    <input type="hidden" name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=catalog">
                    <button type="submit" class="btn-delete" title="Sil"><i class="fas fa-trash"></i></button>
                  </form>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Add Source Form -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon brand"><i class="fas fa-plus-circle"></i></span> Yeni Kaynak Ekle</h2>
      </div>
      <div class="card-body">
        <form method="post" action="sources_manager.php">
          <input type="hidden" name="add_source" value="1">
          <input type="hidden" name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=catalog">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
            <div class="field">
              <label>Kaynak Adı *</label>
              <input type="text" name="name" placeholder="örn: Emerging Threats" required>
            </div>
            <div class="field">
              <label>URL *</label>
              <input type="url" name="url" placeholder="https://example.com/blocklist.txt" required>
            </div>
            <div class="field">
              <label>Tip *</label>
              <select name="type">
                <option value="plain">Plain Text</option>
                <option value="netset">NetSet (FireHOL)</option>
                <option value="csv">CSV</option>
              </select>
            </div>
            <div class="field">
              <label>Güncelleme Aralığı</label>
              <select name="update_interval">
                <option value="1800">30 Dakika</option>
                <option value="3600" selected>1 Saat</option>
                <option value="21600">6 Saat</option>
                <option value="86400">24 Saat</option>
              </select>
            </div>
            <!-- R35 (T2.5): default_confidence per source -->
            <div class="field">
              <label>Default Güven Skoru <span style="font-weight:400;color:var(--text-muted);">— <span id="src-conf-val">60</span>/100</span></label>
              <input type="range" name="default_confidence" min="0" max="100" step="5" value="60"
                     style="width:100%;accent-color:#16a085;"
                     oninput="document.getElementById('src-conf-val').textContent=this.value;">
              <div class="field-help" style="font-size:11px;color:var(--text-muted);">
                Spamhaus/DROP ≥95 · Firehol L1 ~85 · Cinsscore ~70 · USOM ~80 · Topluluk feed ~50
              </div>
            </div>
            <div class="field" style="grid-column:1/-1;">
              <label>Açıklama</label>
              <input type="text" name="description" placeholder="Kaynak hakkında kısa not">
            </div>
            <div class="field" style="grid-column:1/-1;display:flex;align-items:center;gap:8px;">
              <input type="checkbox" name="enabled" id="src-enabled" checked style="width:auto;">
              <label for="src-enabled" style="margin:0;">Bu kaynağı aktif et</label>
            </div>
          </div>
          <button type="submit" class="btn btn-primary"><i class="fas fa-plus"></i> Kaynak Ekle</button>
        </form>
      </div>
    </div>

    <!-- Recommended Sources (by category) -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon slate"><i class="fas fa-lightbulb"></i></span> Tavsiye Edilen Kaynaklar</h2>
        <span style="font-size:11.5px;color:var(--text-muted);">Eklediğinizde aktif değil olarak gelir; tipine göre doğru dinamik dizine düşer.</span>
      </div>
      <?php
      $existing_urls = array_map(fn($s) => $s['url'] ?? '', $configured_sources);
      $recommended = [
        'IP / CIDR → Firewall (FortiGate / F5 AFM)' => [
          ['Spamhaus DROP', 'IP — Tehlikeli ağ blokları', 'plain', 'https://www.spamhaus.org/drop/drop.txt'],
          ['Spamhaus EDROP', 'IP — Uzantı (EDROP)', 'plain', 'https://www.spamhaus.org/drop/edrop.txt'],
          ['FireHOL Level 1', 'IP — Yüksek güven blocklist', 'netset', 'https://iplists.firehol.org/files/firehol_level1.netset'],
          ['Feodo Tracker IP Blocklist', 'IP — Bot C&C', 'plain', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'],
          ['Emerging Threats Compromised IPs', 'IP — Ele geçirilmiş hostlar', 'plain', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'],
          ['Blocklist.de All', 'IP — Saldırı kaynak IP havuzu', 'plain', 'https://lists.blocklist.de/lists/all.txt'],
          ['CINS Score Army', 'IP — Sentinel IPS', 'plain', 'https://cinsscore.com/list/ci-badguys.txt'],
          ['Tor Exit Nodes', 'IP — Anonim trafik', 'plain', 'https://check.torproject.org/torbulkexitlist'],
        ],
        'Domain / FQDN → DNS RPZ / WAF' => [
          ['URLhaus Hosts (domain)', 'Domain — Malware host', 'plain', 'https://urlhaus.abuse.ch/downloads/hostfile/'],
          ['StevenBlack Hosts', 'Domain — Geniş malware/reklam listesi', 'plain', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'],
          ['OpenPhish Hosts', 'Domain — Phishing host', 'plain', 'https://openphish.com/feed.txt'],
          ['USOM TR-CERT (domain)', 'Domain — TR-CERT (450K+)', 'plain', 'https://www.usom.gov.tr/url-list.txt'],
          ['Malware Domain List', 'Domain — Aktif malware host', 'plain', 'https://mirror1.malwaredomains.com/files/justdomains'],
        ],
        'URL → WAF (F5 ASM / ModSecurity)' => [
          ['URLhaus URL Feed', 'URL — Malware dağıtım URL\'leri', 'plain', 'https://urlhaus.abuse.ch/downloads/text/'],
          ['OpenPhish URLs', 'URL — Phishing URL feed', 'plain', 'https://openphish.com/feed.txt'],
          ['PhishTank Verified', 'URL — Doğrulanmış phishing', 'csv', 'https://data.phishtank.com/data/online-valid.csv'],
        ],
        'IoC / Hash → SIEM / EDR' => [
          ['MalwareBazaar Recent MD5', 'IoC — MD5 hash', 'plain', 'https://bazaar.abuse.ch/export/txt/md5/recent/'],
          ['MalwareBazaar Recent SHA256', 'IoC — SHA256 hash', 'plain', 'https://bazaar.abuse.ch/export/txt/sha256/recent/'],
        ],
      ];
      ?>
      <?php foreach ($recommended as $category => $items): ?>
      <div style="padding:14px 18px 6px;border-top:1px solid var(--border);background:var(--slate-50);">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);font-weight:600;">
          <?= htmlspecialchars($category) ?>
        </div>
      </div>
      <div class="card-body flush">
        <div class="table-responsive">
          <table class="data-table" style="font-size:12.5px;">
            <thead>
              <tr><th>Kaynak</th><th>Kategori</th><th>Format</th><th>URL</th><th style="text-align:right;">İşlem</th></tr>
            </thead>
            <tbody>
              <?php foreach ($items as $r):
                $is_added = in_array($r[3], $existing_urls); ?>
              <tr>
                <td><strong style="color:var(--text);"><?= htmlspecialchars($r[0]) ?></strong></td>
                <td style="color:var(--text-muted);"><?= htmlspecialchars($r[1]) ?></td>
                <td><span class="badge badge-source"><?= htmlspecialchars($r[2]) ?></span></td>
                <td class="mono" style="font-size:11px;color:var(--text-muted);word-break:break-all;"><?= htmlspecialchars($r[3]) ?></td>
                <td style="text-align:right;white-space:nowrap;">
                  <?php if ($is_added): ?>
                    <span class="badge badge-whitelist"><i class="fas fa-check"></i> Eklendi</span>
                  <?php else: ?>
                    <form method="post" action="sources_manager.php" style="display:inline;">
                      <input type="hidden" name="add_source" value="1">
          <input type="hidden" name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=catalog">
                      <input type="hidden" name="name" value="<?= htmlspecialchars($r[0]) ?>">
                      <input type="hidden" name="url" value="<?= htmlspecialchars($r[3]) ?>">
                      <input type="hidden" name="type" value="<?= htmlspecialchars($r[2]) ?>">
                      <input type="hidden" name="description" value="<?= htmlspecialchars($r[1]) ?>">
                      <input type="hidden" name="update_interval" value="3600">
                      <button type="submit" class="btn btn-ghost btn-sm"><i class="fas fa-plus"></i> Ekle</button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
      <?php endforeach; ?>
    </div>

    <!-- Sistem Yönetimi -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon slate"><i class="fas fa-cog"></i></span> Sistem Yönetimi</h2>
      </div>
      <div class="card-body" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;">
        <div style="padding:12px;border:1px solid var(--border);border-radius:8px;">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:4px;">Crontab</div>
          <div style="font-size:14px;font-weight:600;color:<?= $crontab_active ? 'var(--success)' : 'var(--warning)' ?>;">
            <i class="fas fa-<?= $crontab_active ? 'check-circle' : 'pause-circle' ?>"></i> <?= $crontab_active ? 'Aktif' : 'Pasif' ?>
          </div>
          <div style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">www-data crontab</div>
        </div>
        <div style="padding:12px;border:1px solid var(--border);border-radius:8px;">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:4px;">Combined Output</div>
          <div class="mono" style="font-size:11.5px;color:var(--text);word-break:break-all;"><?= htmlspecialchars($settings_data['combined_file'] ?? '-') ?></div>
        </div>
        <div style="padding:12px;border:1px solid var(--border);border-radius:8px;">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:4px;">Whitelist Dosyası</div>
          <div class="mono" style="font-size:11.5px;color:var(--text);word-break:break-all;"><?= htmlspecialchars($settings_data['whitelist_file'] ?? '-') ?></div>
        </div>
        <div style="padding:12px;border:1px solid var(--border);border-radius:8px;">
          <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:4px;">Log Dosyası</div>
          <div class="mono" style="font-size:11.5px;color:var(--text);word-break:break-all;"><?= htmlspecialchars($settings_data['log_file'] ?? '-') ?></div>
        </div>
      </div>
    </div>

    <!-- Below: legacy static reference catalog (kept as quick lookup) -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon slate"><i class="fas fa-list"></i></span> Hızlı Referans Kataloğu</h2>
      </div>
      <div class="card-body" style="background:var(--info-bg);color:#1e3a8a;font-size:13px;line-height:1.6;border-bottom:1px solid #bfdbfe;">
        <i class="fas fa-info-circle" style="margin-right:6px;"></i>
        Yukarıdaki Sources Manager dinamik kaynak yönetimini yapar (config + fetch). Aşağıdaki tablo
        kürate edilmiş popüler kaynakların hızlı referansıdır — URL'i kopyalayıp Sources Manager'a ekleyebilirsin.
      </div>
      <div class="card-body flush">
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:22%;">Kaynak</th>
                <th>Tip</th>
                <th style="width:34%;">Açıklama</th>
                <th>Lisans</th>
                <th>Kayıt</th>
                <th style="text-align:right;">İşlem</th>
              </tr>
            </thead>
            <tbody>
              <?php
              $catalog = [
                ['name'=>'USOM (TR-CERT)',           'type'=>'ip,domain,url','desc'=>'Türkiye Ulusal Siber Olaylara Müdahale Merkezi — devlet onaylı zararlı adres listesi.','license'=>'Açık','count'=>'~473K','url'=>'https://www.usom.gov.tr/api/address/index','tag'=>'usom','enabled'=>true],
                ['name'=>'Spamhaus DROP',           'type'=>'ipv4 CIDR',    'desc'=>'Don\'t Route Or Peer — known hijacked netblocks.','license'=>'Free/Comm','count'=>'~1.2K','url'=>'https://www.spamhaus.org/drop/drop.txt','tag'=>'spamhaus_drop'],
                ['name'=>'Spamhaus EDROP',          'type'=>'ipv4 CIDR',    'desc'=>'Extended DROP — additional hijacked blocks.','license'=>'Free/Comm','count'=>'~200','url'=>'https://www.spamhaus.org/drop/edrop.txt','tag'=>'spamhaus_edrop'],
                ['name'=>'Emerging Threats — Compromised',  'type'=>'ipv4',  'desc'=>'Bilinen compromise edilmiş IP\'ler (Proofpoint).','license'=>'Açık','count'=>'~500','url'=>'https://rules.emergingthreats.net/blockrules/compromised-ips.txt','tag'=>'et_compromised'],
                ['name'=>'CINS Score Army',         'type'=>'ipv4',         'desc'=>'Sentinel IPS — pozitif IDS skoru yüksek IP\'ler.','license'=>'Açık','count'=>'~15K','url'=>'https://cinsscore.com/list/ci-badguys.txt','tag'=>'cins'],
                ['name'=>'FireHOL Level 1',         'type'=>'ipv4 CIDR',    'desc'=>'En sıkı FireHOL listesi — false-positive riski düşük.','license'=>'Açık','count'=>'~600','url'=>'https://iplists.firehol.org/files/firehol_level1.netset','tag'=>'firehol_l1'],
                ['name'=>'FireHOL Level 2',         'type'=>'ipv4 CIDR',    'desc'=>'Saatlik güncellenen, daha agresif liste.','license'=>'Açık','count'=>'~2K','url'=>'https://iplists.firehol.org/files/firehol_level2.netset','tag'=>'firehol_l2'],
                ['name'=>'AbuseIPDB Blacklist',     'type'=>'ipv4',         'desc'=>'Topluluk raporlu kötüye kullanım IP\'leri.','license'=>'API key','count'=>'~10K','url'=>'https://api.abuseipdb.com/api/v2/blacklist','tag'=>'abuseipdb'],
                ['name'=>'Feodo Tracker — Botnet C2','type'=>'ipv4',        'desc'=>'Emotet/Dridex/TrickBot C2 IP listesi (abuse.ch).','license'=>'Açık','count'=>'~400','url'=>'https://feodotracker.abuse.ch/downloads/ipblocklist.txt','tag'=>'feodo'],
                ['name'=>'URLhaus — Malware URL\'leri','type'=>'url,domain','desc'=>'Aktif malware dağıtım URL\'leri (abuse.ch).','license'=>'Açık','count'=>'~3K','url'=>'https://urlhaus.abuse.ch/downloads/text/','tag'=>'urlhaus'],
                ['name'=>'OpenPhish',               'type'=>'url',          'desc'=>'Doğrulanmış aktif phishing URL\'leri.','license'=>'Free tier','count'=>'~2K','url'=>'https://openphish.com/feed.txt','tag'=>'openphish'],
                ['name'=>'PhishTank',               'type'=>'url',          'desc'=>'Topluluk doğrulamalı phishing URL veritabanı.','license'=>'Açık','count'=>'~25K','url'=>'http://data.phishtank.com/data/online-valid.csv','tag'=>'phishtank'],
                ['name'=>'Malware Domain List',     'type'=>'domain',       'desc'=>'Aktif malware barındıran alan adları.','license'=>'Açık','count'=>'~5K','url'=>'https://mirror1.malwaredomains.com/files/justdomains','tag'=>'malwaredomains'],
                ['name'=>'AlienVault OTX',          'type'=>'ipv4,domain,url','desc'=>'Open Threat Exchange (community + AT&T pulses).','license'=>'API key','count'=>'Değişken','url'=>'https://otx.alienvault.com/api','tag'=>'otx'],
                ['name'=>'Tor Exit Nodes',          'type'=>'ipv4',         'desc'=>'Anonim trafiği engellemek için aktif Tor exit IP\'leri.','license'=>'Açık','count'=>'~1.5K','url'=>'https://check.torproject.org/torbulkexitlist','tag'=>'tor'],
              ];
              foreach ($catalog as $c):
                $type_badges = '';
                foreach (explode(',', $c['type']) as $t) {
                  $type_badges .= '<span class="badge badge-source" style="margin-right:3px;">'.htmlspecialchars(trim($t)).'</span>';
                }
                $isEnabled = !empty($c['enabled']);
              ?>
              <?php
                // Bu kaynak zaten yapılandırılmış mı?
                $already_configured = false;
                foreach ($configured_sources as $cs) {
                  if (($cs['url'] ?? '') === $c['url']) { $already_configured = true; break; }
                }
              ?>
              <tr>
                <td>
                  <strong style="color:var(--text);"><?= htmlspecialchars($c['name']) ?></strong><br>
                  <a href="<?= htmlspecialchars($c['url']) ?>" target="_blank" rel="noopener" style="font-size:11px;color:var(--text-muted);word-break:break-all;">
                    <?= htmlspecialchars($c['url']) ?> <i class="fas fa-external-link-alt" style="font-size:9px;"></i>
                  </a>
                </td>
                <td><?= $type_badges ?></td>
                <td style="font-size:12.5px;color:var(--text-muted);"><?= htmlspecialchars($c['desc']) ?></td>
                <td><span class="badge badge-source"><?= htmlspecialchars($c['license']) ?></span></td>
                <td class="tabular mono" style="font-size:12px;"><?= htmlspecialchars($c['count']) ?></td>
                <td style="text-align:right;">
                  <?php if ($already_configured || !empty($c['enabled'])): ?>
                    <span class="badge badge-whitelist"><i class="fas fa-check"></i> Eklenmiş</span>
                  <?php else: ?>
                    <form method="post" action="sources_manager.php" style="display:inline;">
                      <input type="hidden" name="add_source" value="1">
                      <input type="hidden" name="name" value="<?= htmlspecialchars($c['name']) ?>">
                      <input type="hidden" name="url" value="<?= htmlspecialchars($c['url']) ?>">
                      <input type="hidden" name="type" value="plain">
                      <input type="hidden" name="description" value="<?= htmlspecialchars($c['desc']) ?>">
                      <input type="hidden" name="update_interval" value="3600">
                      <input type="hidden" name="return_to" value="cyberwebeyeosblacklistadmin.php?tab=catalog">
                      <button type="submit" class="btn btn-primary btn-sm" title="Sources Manager'a ekle">
                        <i class="fas fa-plus"></i> Ekle
                      </button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon slate"><i class="fas fa-lightbulb"></i></span> Notlar</h2>
      </div>
      <div class="card-body" style="font-size:13px;line-height:1.7;color:var(--text-muted);">
        <ul style="padding-left:22px;">
          <li><strong style="color:var(--text);">USOM</strong> şu an aktif olarak çekiliyor (cron + USOM API). Diğer kaynaklar F2 fazında otomatik fetcher ile entegre edilecek.</li>
          <li><strong style="color:var(--text);">Lisans</strong> sütunu: "Açık" = ücretsiz public, "API key" = ücretsiz tier veya kayıt gerekli, "Free/Comm" = küçük org için ücretsiz, kurumsal için ücretli.</li>
          <li><strong style="color:var(--text);">Performans:</strong> Çok büyük feed'leri (URLhaus gibi) eklemek RAM/disk gerektirir. Production'da kategorize edilmeli.</li>
          <li><strong style="color:var(--text);">False positive:</strong> Spamhaus DROP, FireHOL L1 ve USOM düşük risk; AbuseIPDB ve PhishTank topluluk-bazlı, yanlış pozitif daha yüksek.</li>
        </ul>
      </div>
    </div>

<!-- SPRINT6-A5 START: Vendor watchlist tuning -->
<section class="vw-tuning" style="margin-top:32px;padding:20px;background:#0f172a;border-radius:10px;border:1px solid #1e293b;">
  <h3 style="margin:0 0 12px 0;color:#16a085;">⚙ Vendor Watchlist Tuning <span style="font-size:11px;color:#64748b;font-weight:normal;">(admin-only)</span></h3>
  <form id="vwForm" onsubmit="return vwSave(event)" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
    <label style="grid-column:1/3;">
      <span style="color:#94a3b8;font-size:12px;">Vendors (virgülle ayrı)</span>
      <input id="vw_vendors" type="text" style="width:100%;padding:8px;background:#020617;color:#e2e8f0;border:1px solid #334155;border-radius:6px;" />
    </label>
    <label>
      <span style="color:#94a3b8;font-size:12px;">Min CVSS (<span id="vw_cvss_val">7.0</span>)</span>
      <input id="vw_min_cvss" type="range" min="5.0" max="9.5" step="0.5" value="7.0"
             oninput="document.getElementById('vw_cvss_val').textContent=this.value" style="width:100%;" />
    </label>
    <label>
      <span style="color:#94a3b8;font-size:12px;">Auto-dismiss days</span>
      <input id="vw_dismiss" type="number" min="1" max="365" value="30" style="width:100%;padding:8px;background:#020617;color:#e2e8f0;border:1px solid #334155;border-radius:6px;" />
    </label>
    <label>
      <span style="color:#94a3b8;font-size:12px;">Fetch window days</span>
      <input id="vw_window" type="number" min="1" max="90" value="7" style="width:100%;padding:8px;background:#020617;color:#e2e8f0;border:1px solid #334155;border-radius:6px;" />
    </label>
    <label style="display:flex;align-items:center;gap:8px;">
      <input id="vw_kev" type="checkbox" checked />
      <span style="color:#cbd5e1;">KEV her zaman dahil</span>
    </label>
    <div style="grid-column:1/3;">
      <button type="submit" style="padding:10px 20px;background:linear-gradient(135deg,#16a085,#0e6655);color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Kaydet</button>
      <span id="vwStatus" style="margin-left:12px;color:#22c55e;display:none;">✓ Kaydedildi</span>
    </div>
  </form>
</section>
<script>
// R88c: vendor_watchlist.json artık server-side inject (R87b .htaccess blanket-deny
// nedeniyle direct HTTP fetch 403 dönüyordu). HTTP fetch yerine PHP'den gömüyoruz.
window.__vendor_watchlist = <?= json_encode(file_exists(__DIR__ . '/vendor_watchlist.json') ? (json_decode(@file_get_contents(__DIR__ . '/vendor_watchlist.json'), true) ?: []) : [], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) ?>;
(function vwInit(){
  try {
    const cfg = window.__vendor_watchlist || {};
    document.getElementById('vw_vendors').value = (cfg.vendors||[]).join(', ');
    document.getElementById('vw_min_cvss').value = cfg.min_cvss || 7.0;
    document.getElementById('vw_cvss_val').textContent = cfg.min_cvss || 7.0;
    document.getElementById('vw_dismiss').value = cfg.auto_dismiss_days || 30;
    document.getElementById('vw_window').value = cfg.fetch_window_days || 7;
    document.getElementById('vw_kev').checked = !!cfg.include_kev_always;
  } catch(e) { console.warn('vw load fail', e); }
})();
async function vwSave(ev){
  ev.preventDefault();
  const fd = new FormData();
  fd.append('vendors', document.getElementById('vw_vendors').value);
  fd.append('min_cvss', document.getElementById('vw_min_cvss').value);
  fd.append('auto_dismiss_days', document.getElementById('vw_dismiss').value);
  fd.append('fetch_window_days', document.getElementById('vw_window').value);
  if (document.getElementById('vw_kev').checked) fd.append('include_kev_always', '1');
  const r = await fetch('vendor_watchlist_save.php', {method:'POST', body:fd});
  const j = await r.json();
  const s = document.getElementById('vwStatus');
  s.style.display = 'inline';
  s.textContent = j.ok ? '✓ Kaydedildi' : '✗ Hata: ' + (j.error || 'unknown');
  s.style.color = j.ok ? '#22c55e' : '#ef4444';
  setTimeout(() => s.style.display='none', 3000);
  return false;
}
</script>
<!-- SPRINT6-A5 END -->

  </div>

  <!-- =================== TAB: LİSTELER (multiple manual lists) =================== -->
  <?php
  $lists_data = @json_decode(@file_get_contents(__DIR__ . '/lists.json'), true) ?? ['lists'=>[]];
  $lists_all  = $lists_data['lists'] ?? [];
  ?>
  <div class="tab-panel" id="tab-lists">
    <div class="main-grid">
      <section>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon brand"><i class="fas fa-layer-group"></i></span> Manuel Listeler</h2>
            <div class="card-actions">
              <span class="badge badge-source"><?= count($lists_all) ?> liste</span>
            </div>
          </div>
          <div class="card-body" style="background:var(--info-bg);color:#1e40af;font-size:13px;line-height:1.6;border-bottom:1px solid #bfdbfe;">
            <i class="fas fa-info-circle" style="margin-right:6px;"></i>
            Birden fazla isimlendirilmiş manuel liste oluşturabilirsin. Her liste belirli tipte
            (IP/Domain/URL/IoC) veya birleşik (merged) olabilir. Her birinin kendi feed URL'i olur,
            firewall/DNS RPZ/WAF ayrı ayrı çekebilir.
          </div>
          <div class="card-body flush">
            <?php if (empty($lists_all)): ?>
              <div class="empty">
                <div class="empty-icon muted"><i class="fas fa-folder-open"></i></div>
                <div class="empty-title">Henüz liste yok</div>
                <div class="empty-desc">Sağdaki form ile yeni liste oluştur.</div>
              </div>
            <?php else: ?>
            <div class="table-responsive">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Liste Adı</th>
                    <th>Tip</th>
                    <th>Slug / Dosya</th>
                    <th class="tabular">Kayıt</th>
                    <th>Oluşturma</th>
                    <th style="text-align:right;">İşlem</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($lists_all as $l):
                    $list_count = _cwe_cached_count($l['file'] ?? '');
                    $type_label = ['merged'=>'Birleşik','ip'=>'IPv4','ipv6'=>'IPv6','domain'=>'Domain','url'=>'URL','ioc'=>'IoC/Hash'][$l['type'] ?? 'merged'] ?? ucfirst($l['type'] ?? 'merged');
                    $type_color = ['merged'=>'badge-manual','ip'=>'badge-whitelist','domain'=>'badge-usom','url'=>'badge-pending','ioc'=>'badge-source'][$l['type'] ?? 'merged'] ?? 'badge-source';
                  ?>
                  <tr>
                    <td>
                      <strong style="color:var(--text);"><?= htmlspecialchars($l['name']) ?></strong>
                      <?php if (!empty($l['system'])): ?><span class="badge badge-source" style="margin-left:6px;font-size:9px;">SYS</span><?php endif; ?>
                      <?php if (!empty($l['description'])): ?><br><span style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($l['description']) ?></span><?php endif; ?>
                    </td>
                    <td><span class="badge <?= $type_color ?>"><?= htmlspecialchars($type_label) ?></span></td>
                    <td class="mono" style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($l['slug'] ?? '-') ?></td>
                    <td class="tabular mono"><?= number_format($list_count, 0, ',', '.') ?></td>
                    <td style="font-size:11.5px;color:var(--text-muted);"><?= htmlspecialchars($l['created_at'] ?? '-') ?></td>
                    <td style="text-align:right;white-space:nowrap;">
                      <a href="<?= htmlspecialchars(basename($l['file'] ?? '')) ?>" target="_blank" class="btn btn-ghost btn-sm" title="Feed.txt aç"><i class="fas fa-file-alt"></i></a>
                      <button type="button" class="btn btn-ghost btn-sm" title="Görüntüle/Düzenle" onclick="showTab('blacklist'); alert('Bu liste şu an Blacklist tab\\'ında düzenleniyor (system list). Yeni liste UI\\'sı F4 fazında.'); return false;"><i class="fas fa-eye"></i></button>
                      <?php if (empty($l['system'])): ?>
                      <form method="post" action="lists.php" style="display:inline;" onsubmit="return confirm('<?= htmlspecialchars($l['name']) ?> listesi silinsin mi?');">
                        <input type="hidden" name="list_delete" value="<?= htmlspecialchars($l['id']) ?>">
                        <button type="submit" class="btn-delete" title="Sil"><i class="fas fa-trash"></i></button>
                      </form>
                      <?php endif; ?>
                    </td>
                  </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <?php endif; ?>
          </div>
        </div>

        <!-- Liste içeriği arama -->
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon info"><i class="fas fa-search"></i></span> Liste İçeriği Ara</h2>
          </div>
          <div class="card-body">
            <form onsubmit="alert('Çapraz liste arama F4 fazında — şu an Blacklist/Whitelist tablarında ayrı ayrı arayabilirsin.'); return false;">
              <div style="display:grid;grid-template-columns:200px 1fr auto;gap:10px;align-items:end;">
                <div class="field" style="margin:0;">
                  <label>Liste Seç</label>
                  <select>
                    <option value="all">Tüm Listeler</option>
                    <?php foreach ($lists_all as $l): ?>
                      <option value="<?= htmlspecialchars($l['id']) ?>"><?= htmlspecialchars($l['name']) ?></option>
                    <?php endforeach; ?>
                    <option value="whitelist">Whitelist</option>
                    <option value="pending">Pending</option>
                  </select>
                </div>
                <div class="field" style="margin:0;">
                  <label>Aranan IP / Domain / URL</label>
                  <input type="text" placeholder="192.0.2.1 veya malware.example.com">
                </div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Ara</button>
              </div>
            </form>
          </div>
        </div>
      </section>

      <aside>
        <!-- Yeni Liste Oluştur -->
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon brand"><i class="fas fa-plus-circle"></i></span> Yeni Liste</h2>
          </div>
          <div class="card-body">
            <form method="post" action="lists.php">
              <input type="hidden" name="list_add" value="1">
              <div class="field">
                <label>Liste Adı *</label>
                <input type="text" name="name" placeholder="örn: Saldırgan IPler" required>
              </div>
              <div class="field">
                <label>Slug *</label>
                <input type="text" name="slug" placeholder="attackers" required>
                <div class="field-help">URL'de görünür: /lists_dyn/&lt;slug&gt;.txt</div>
              </div>
              <div class="field">
                <label>Tip *</label>
                <select name="type">
                  <option value="merged">Birleşik (her tip)</option>
                  <option value="ip">IPv4</option>
                  <option value="ipv6">IPv6</option>
                  <option value="cidr">CIDR</option>
                  <option value="domain">Domain / FQDN</option>
                  <option value="url">URL</option>
                  <option value="ioc">IoC / Hash</option>
                </select>
              </div>
              <div class="field">
                <label>Açıklama</label>
                <input type="text" name="description" placeholder="Bu listenin amacı">
              </div>
              <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-plus"></i> Liste Oluştur</button>
            </form>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon info"><i class="fas fa-lightbulb"></i></span> Tipik Kullanım</h2>
          </div>
          <div class="card-body" style="font-size:12.5px;color:var(--text-muted);line-height:1.7;">
            <ul style="padding-left:20px;">
              <li><strong style="color:var(--text);">merged</strong> — Firewall'a tek URL ile her şey: <code>cyberwebeyeosblacklist.txt</code></li>
              <li><strong style="color:var(--text);">ip</strong> — Sadece IPv4 → FortiGate IP Threat Feed</li>
              <li><strong style="color:var(--text);">domain</strong> — Sadece domain → DNS RPZ / WAF</li>
              <li><strong style="color:var(--text);">url</strong> — Sadece URL → WAF / Proxy</li>
              <li><strong style="color:var(--text);">ioc</strong> — Hash → SIEM / EDR</li>
            </ul>
          </div>
        </div>
      </aside>
    </div>
  </div>

  <!-- =================== TAB: KULLANICILAR =================== -->
  <?php
  $users_data = @json_decode(@file_get_contents(__DIR__ . '/users.json'), true) ?? ['users'=>[]];
  $users_list = $users_data['users'] ?? [];
  ?>
  <div class="tab-panel" id="tab-users">
    <div class="main-grid">
      <section>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon brand"><i class="fas fa-users"></i></span> Kullanıcılar</h2>
            <div class="card-actions">
              <span class="badge badge-source"><?= count($users_list) ?> kullanıcı</span>
            </div>
          </div>
          <div class="card-body flush">
            <?php if (empty($users_list)): ?>
              <div class="empty">
                <div class="empty-icon muted"><i class="fas fa-user-slash"></i></div>
                <div class="empty-title">Henüz kullanıcı yok</div>
                <div class="empty-desc">Sağdaki form ile yeni kullanıcı ekle.</div>
              </div>
            <?php else: ?>
            <div class="table-responsive">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Kullanıcı</th>
                    <th>E-posta</th>
                    <th>Rol</th>
                    <th>Oluşturma</th>
                    <th>Son Giriş</th>
                    <th>Durum</th>
                    <th style="text-align:right;">İşlem</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($users_list as $u): ?>
                  <tr>
                    <td>
                      <div style="display:flex;align-items:center;gap:10px;">
                        <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--brand-400),var(--brand-700));color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;"><?= strtoupper(substr($u['username'], 0, 1)) ?></div>
                        <strong style="color:var(--text);"><?= htmlspecialchars($u['username']) ?></strong>
                      </div>
                    </td>
                    <td style="color:var(--text-muted);"><?= htmlspecialchars($u['email'] ?? '-') ?></td>
                    <td><span class="badge <?= ($u['role'] ?? '') === 'admin' ? 'badge-manual' : 'badge-source' ?>"><?= htmlspecialchars(ucfirst($u['role'] ?? 'viewer')) ?></span></td>
                    <td style="font-size:11.5px;color:var(--text-muted);"><?= htmlspecialchars(substr($u['created_at'] ?? '-', 0, 16)) ?></td>
                    <td style="font-size:11.5px;color:var(--text-muted);"><?= htmlspecialchars($u['last_login'] ?? 'Hiç') ?></td>
                    <td>
                      <?php if (!empty($u['active'])): ?>
                        <span class="badge badge-whitelist"><i class="fas fa-check"></i> Aktif</span>
                      <?php else: ?>
                        <span class="badge badge-source"><i class="fas fa-times"></i> Pasif</span>
                      <?php endif; ?>
                    </td>
                    <td style="text-align:right;white-space:nowrap;">
                      <form method="post" action="users.php" style="display:inline;">
                        <input type="hidden" name="user_toggle" value="<?= htmlspecialchars($u['id']) ?>">
                        <button type="submit" class="btn btn-ghost btn-sm" title="<?= !empty($u['active'])?'Pasif yap':'Aktif yap' ?>"><i class="fas fa-<?= !empty($u['active'])?'pause':'play' ?>"></i></button>
                      </form>
                      <?php if ($u['id'] !== 'u_default' && ($u['username'] ?? '') !== 'cyberwebeyeos'): ?>
                      <form method="post" action="users.php" style="display:inline;" onsubmit="return confirm('<?= htmlspecialchars($u['username']) ?> kullanıcısı silinsin mi?');">
                        <input type="hidden" name="user_delete" value="<?= htmlspecialchars($u['id']) ?>">
                        <button type="submit" class="btn-delete" title="Sil"><i class="fas fa-trash"></i></button>
                      </form>
                      <?php endif; ?>
                    </td>
                  </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <?php endif; ?>
          </div>
        </div>

        <!-- Activity log placeholder -->
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon slate"><i class="fas fa-history"></i></span> Kullanıcı Aktivite Takibi</h2>
          </div>
          <div class="card-body">
            <div class="empty" style="padding:32px 16px;">
              <div class="empty-icon muted"><i class="fas fa-stream"></i></div>
              <div class="empty-title">Audit log AKTİF ✓</div>
              <div class="empty-desc"><a href="?tab=status" onclick="showTab('status');return false;" style="color:var(--brand-700);">→ Durum & Loglar tab'a git</a> — her kullanıcı işlemi (giriş, IP ekleme/silme/onay vs.) loglu.</div>
            </div>
          </div>
        </div>
      </section>

      <aside>
        <!-- Yeni Kullanıcı Ekle -->
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon brand"><i class="fas fa-user-plus"></i></span> Yeni Kullanıcı</h2>
          </div>
          <div class="card-body">
            <form method="post" action="users.php">
              <input type="hidden" name="user_add" value="1">
              <div class="field">
                <label>Kullanıcı Adı *</label>
                <input type="text" name="username" placeholder="kullanici_adi" required>
              </div>
              <div class="field">
                <label>E-posta</label>
                <input type="email" name="email" placeholder="user@example.com">
              </div>
              <div class="field">
                <label>Parola *</label>
                <input type="password" name="password" placeholder="En az 8 karakter" minlength="8" required>
              </div>
              <div class="field">
                <label>Rol</label>
                <select name="role">
                  <option value="viewer">Viewer (sadece okuma)</option>
                  <option value="operator">Operator (CRUD)</option>
                  <option value="admin" selected>Admin (tam yetki)</option>
                </select>
              </div>
              <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-user-plus"></i> Kullanıcı Ekle</button>
            </form>
          </div>
        </div>

        <!-- Mevcut Auth Bilgisi -->
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon info"><i class="fas fa-key"></i></span> Auth Bilgisi</h2>
          </div>
          <div class="card-body" style="font-size:13px;line-height:1.7;">
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">Aktif kullanıcı</span>
              <span class="mono"><?= htmlspecialchars($current_user) ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">Session</span>
              <span class="mono" style="font-size:11px;">CWE_BLACKLIST_SESSION</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:4px 0;">
              <span style="color:var(--text-muted);">Auth tipi</span>
              <span class="badge badge-manual">PHP Session</span>
            </div>
            <details style="margin-top:14px;border:1px solid var(--border);border-radius:8px;padding:10px 12px;">
              <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text);"><i class="fas fa-key"></i> Parolamı Değiştir</summary>
              <form method="post" action="users.php" style="margin-top:12px;">
                <?php $cu_id = 'u_default'; foreach ($users_list as $uu) { if (($uu['username'] ?? '') === $current_user) { $cu_id = $uu['id']; break; } } ?>
                <input type="hidden" name="user_change_password" value="<?= htmlspecialchars($cu_id) ?>">
                <div class="field"><label>Mevcut Parola</label><input type="password" name="old_password" required></div>
                <div class="field"><label>Yeni Parola (min 8)</label><input type="password" name="new_password" minlength="8" required></div>
                <div class="field"><label>Yeni Parola Tekrar</label><input type="password" name="new_password2" minlength="8" required></div>
                <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-check"></i> Parolayı Güncelle</button>
              </form>
            </details>
            <div style="margin-top:12px;font-size:12px;background:var(--info-bg);color:#1e40af;padding:10px 12px;border-radius:6px;">
              <i class="fas fa-info-circle"></i> Çoklu kullanıcı + bcrypt + role aktif. <strong>Audit log AKTİF</strong> + parola değiştirme yukarıdaki accordion'dan. REST API: <code>api.php</code> (X-API-Key auth, /auth_config.php → api_keys).
            </div>
          </div>
        </div>
      </aside>
    </div>
  </div>

  <!-- =================== TAB: DASHBOARD (T3.3) =================== -->
  <div class="tab-panel" id="tab-dashboard">
    <!-- KPI tile row (üstte, hızlı bakış) -->
    <div id="dash-totals" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:18px;">
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff 0%,var(--slate-50) 100%);border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;">Blacklist</div>
        <div id="t-bl" style="font-size:24px;font-weight:700;color:#16a085;margin-top:4px;">—</div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff 0%,var(--slate-50) 100%);border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;">Whitelist</div>
        <div id="t-wl" style="font-size:24px;font-weight:700;color:#10b981;margin-top:4px;">—</div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff 0%,var(--slate-50) 100%);border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;">Pending</div>
        <div id="t-pn" style="font-size:24px;font-weight:700;color:#f59e0b;margin-top:4px;">—</div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff 0%,var(--slate-50) 100%);border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;">Expired</div>
        <div id="t-ex" style="font-size:24px;font-weight:700;color:#dc2626;margin-top:4px;">—</div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff 0%,var(--slate-50) 100%);border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;">FP Raporları</div>
        <div id="t-fp" style="font-size:24px;font-weight:700;color:#8b5cf6;margin-top:4px;">—</div>
      </div>
    </div>

    <!-- Chart grid — fixed 2-column, fixed canvas height = predictable layout -->
    <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;">
      <div class="card">
        <div class="card-head">
          <h2><span class="h2-icon" style="background:#dcfce7;color:#166534;"><i class="fas fa-chart-line"></i></span> Son 30 Gün — IoC Trendi</h2>
        </div>
        <div class="card-body" style="height:240px;">
          <canvas id="chart-trend"></canvas>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2><span class="h2-icon" style="background:#ede9fe;color:#5b21b6;"><i class="fas fa-shapes"></i></span> IoC Tipi Dağılımı</h2>
        </div>
        <div class="card-body" style="height:240px;">
          <canvas id="chart-type"></canvas>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2><span class="h2-icon" style="background:#fef3c7;color:#92400e;"><i class="fas fa-flag"></i></span> TLP Dağılımı</h2>
        </div>
        <div class="card-body" style="height:240px;">
          <canvas id="chart-tlp"></canvas>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2><span class="h2-icon" style="background:#dbeafe;color:#1e40af;"><i class="fas fa-database"></i></span> Kaynak Katkısı</h2>
        </div>
        <div class="card-body" style="height:240px;">
          <canvas id="chart-source"></canvas>
        </div>
      </div>
    </div>

    <div style="text-align:right;font-size:11px;color:var(--text-muted);margin-top:10px;">
      Son güncelleme: <span id="dash-generated-at">yükleniyor...</span>
    </div>
  </div>

  <!-- =================== TAB: CVE (R43 T4.3) =================== -->
  <div class="tab-panel" id="tab-cve">
    <?php
    $__cves = $__cve_data['cves'] ?? [];
    $__wl_cfg = @json_decode(@file_get_contents(__DIR__ . '/vendor_watchlist.json'), true);
    $__cve_kev_total = 0; $__cve_dismissed = 0; $__cve_crit = 0;
    foreach ($__cves as $cv) {
        if (!empty($cv['dismissed_at'])) { $__cve_dismissed++; continue; }
        if (!empty($cv['is_kev'])) $__cve_kev_total++;
        if (($cv['cvss_score'] ?? 0) >= 9.0) $__cve_crit++;
    }
    $__cve_can_admin = (function_exists('cwe_current_role') && in_array(cwe_current_role(), ['admin','operator'], true));
    ?>

    <!-- KPI bandı -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:16px;">
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff,var(--slate-50));border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Açık CVE</div>
        <div style="font-size:22px;font-weight:700;color:#0ea5e9;margin-top:4px;"><?= number_format($__cve_open) ?></div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#fef2f2,#fee2e2);border:1px solid #fecaca;">
        <div style="font-size:11px;color:#991b1b;text-transform:uppercase;">KEV (Aktif Sömürü)</div>
        <div style="font-size:22px;font-weight:700;color:#dc2626;margin-top:4px;"><?= number_format($__cve_kev_open) ?></div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff,var(--slate-50));border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Kritik (CVSS≥9)</div>
        <div style="font-size:22px;font-weight:700;color:#f59e0b;margin-top:4px;"><?= number_format($__cve_crit) ?></div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff,var(--slate-50));border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Dismissed</div>
        <div style="font-size:22px;font-weight:700;color:#64748b;margin-top:4px;"><?= number_format($__cve_dismissed) ?></div>
      </div>
      <div class="kpi" style="padding:12px 14px;border-radius:10px;background:linear-gradient(135deg,#ffffff,var(--slate-50));border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Toplam</div>
        <div style="font-size:22px;font-weight:700;color:#0f172a;margin-top:4px;"><?= number_format(count($__cves)) ?></div>
      </div>
    </div>

    <!-- Filter chip'leri + sync button -->
    <div class="card" style="margin-bottom:14px;">
      <div class="card-body">
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
          <label style="font-size:12px;font-weight:600;color:var(--text-muted);">Filtre:</label>
          <button type="button" data-filter="open" class="cve-fchip" style="padding:5px 12px;border:1px solid var(--border);border-radius:99px;background:#0ea5e9;color:#fff;cursor:pointer;font-size:11.5px;font-weight:600;">Açık</button>
          <button type="button" data-filter="kev" class="cve-fchip" style="padding:5px 12px;border:1px solid var(--border);border-radius:99px;background:#fff;cursor:pointer;font-size:11.5px;font-weight:600;">🚨 KEV</button>
          <button type="button" data-filter="critical" class="cve-fchip" style="padding:5px 12px;border:1px solid var(--border);border-radius:99px;background:#fff;cursor:pointer;font-size:11.5px;font-weight:600;">CVSS≥9</button>
          <button type="button" data-filter="all" class="cve-fchip" style="padding:5px 12px;border:1px solid var(--border);border-radius:99px;background:#fff;cursor:pointer;font-size:11.5px;font-weight:600;">Tümü</button>
          <button type="button" data-filter="dismissed" class="cve-fchip" style="padding:5px 12px;border:1px solid var(--border);border-radius:99px;background:#fff;cursor:pointer;font-size:11.5px;font-weight:600;">Dismissed</button>
          <span style="margin-left:auto;font-size:11px;color:var(--text-muted);">
            Last sync: <code><?= htmlspecialchars($__cve_data['last_sync'] ?? '-') ?></code>
            · Watch: <code><?= htmlspecialchars(implode(',', $__wl_cfg['vendors'] ?? [])) ?></code>
          </span>
          <?php if ($__cve_can_admin && cwe_current_role() === 'admin'): ?>
          <button type="button" onclick="cveSync()" class="btn btn-success" style="padding:5px 12px;font-size:11.5px;">
            <i class="fas fa-sync"></i> Sync
          </button>
          <?php endif; ?>
        </div>
        <pre id="cve-sync-result" style="display:none;background:var(--slate-50);padding:10px;border-radius:6px;font-size:11px;max-height:140px;overflow-y:auto;font-family:'Fira Code',monospace;margin-top:10px;"></pre>
      </div>
    </div>

    <!-- CVE tablo -->
    <div class="card">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#fee2e2;color:#991b1b;"><i class="fas fa-shield-virus"></i></span> Zafiyetler</h2>
        <span class="badge badge-source" id="cve-count-badge">—</span>
      </div>
      <div class="card-body flush">
        <?php if (empty($__cves)): ?>
          <div class="empty" style="padding:40px 16px;text-align:center;">
            <div class="empty-icon muted"><i class="fas fa-shield-virus"></i></div>
            <div class="empty-title">Henüz CVE çekilmedi</div>
            <div class="empty-desc">Admin'sen <b>Sync</b> butonuna bas. CLI: <code>php cve_fetch.php --bootstrap</code></div>
          </div>
        <?php else: ?>
          <div class="table-responsive">
            <table class="data-table" id="cve-table">
              <thead><tr>
                <th>CVE</th><th>CVSS</th><th title="Exploit Prediction Scoring System (30g)">EPSS</th><th>KEV</th><th>Vendor</th><th>Yayın</th><th>Açıklama</th><th>İşlem</th>
              </tr></thead>
              <tbody>
              <?php
              uasort($__cves, function($a, $b) {
                  $kdiff = (int)(!empty($b['is_kev'])) - (int)(!empty($a['is_kev']));
                  if ($kdiff !== 0) return $kdiff;
                  $cdiff = (float)($b['cvss_score'] ?? 0) <=> (float)($a['cvss_score'] ?? 0);
                  if ($cdiff !== 0) return $cdiff;
                  return strcmp($b['published'] ?? '', $a['published'] ?? '');
              });
              foreach ($__cves as $cid => $cv):
                $is_dismissed = !empty($cv['dismissed_at']);
                $is_kev = !empty($cv['is_kev']);
                $cvss = $cv['cvss_score'] ?? null;
                $sev_color = is_null($cvss) ? '#94a3b8'
                           : ($cvss >= 9.0 ? '#dc2626'
                              : ($cvss >= 7.0 ? '#f59e0b'
                                 : ($cvss >= 4.0 ? '#0ea5e9' : '#10b981')));
                $row_classes = ['cve-row'];
                if ($is_dismissed) $row_classes[] = 'cve-dismissed';
                else $row_classes[] = 'cve-open';
                if ($is_kev) $row_classes[] = 'cve-kev';
                if (($cvss ?? 0) >= 9.0) $row_classes[] = 'cve-critical';
              ?>
                <tr class="<?= implode(' ', $row_classes) ?>" data-cve="<?= htmlspecialchars($cid) ?>" style="<?= $is_dismissed ? 'opacity:0.5;' : '' ?>">
                  <td style="font-family:'Fira Code',monospace;font-size:11.5px;font-weight:600;">
                    <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($cid) ?>" target="_blank" rel="noopener" style="color:#0ea5e9;"><?= htmlspecialchars($cid) ?></a>
                  </td>
                  <td>
                    <?php if (!is_null($cvss)): ?>
                      <span style="background:<?= $sev_color ?>;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;font-family:'Fira Code',monospace;"><?= number_format($cvss, 1) ?></span>
                    <?php else: ?>
                      <span style="color:#94a3b8;font-size:11px;">—</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <?php
                    $__epss = $cv['epss_score'] ?? null;
                    $__epss_pct = $cv['epss_percentile'] ?? null;
                    if (!is_null($__epss)):
                        $__epc = $__epss >= 0.5 ? '#dc2626' : ($__epss >= 0.1 ? '#f59e0b' : ($__epss >= 0.01 ? '#0ea5e9' : '#94a3b8'));
                        $__epp = $__epss_pct ? round($__epss_pct * 100, 1) . '%' : '';
                    ?>
                      <span title="EPSS skor (sömürü olasılığı 30g) · Percentile <?= htmlspecialchars($__epp) ?>" style="background:<?= $__epc ?>20;color:<?= $__epc ?>;padding:2px 7px;border-radius:4px;font-size:10.5px;font-weight:700;font-family:'Fira Code',monospace;"><?= number_format($__epss * 100, 1) ?>%</span>
                    <?php else: ?>
                      <span style="color:#94a3b8;font-size:10.5px;">—</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <?php if ($is_kev): ?>
                      <span title="CISA Known Exploited Vulnerability — aktif sömürü" style="background:#dc2626;color:#fff;padding:2px 7px;border-radius:4px;font-size:10.5px;font-weight:700;">🚨 KEV</span>
                    <?php endif; ?>
                  </td>
                  <td style="font-size:11px;color:#475569;text-transform:capitalize;"><?= htmlspecialchars($cv['matched_vendor'] ?? ($cv['kev_meta']['vendorProject'] ?? '-')) ?></td>
                  <td style="font-size:11px;color:#64748b;white-space:nowrap;"><?= htmlspecialchars(substr($cv['published'] ?? '-', 0, 10)) ?></td>
                  <td style="font-size:11.5px;color:#334155;"><?= htmlspecialchars(mb_substr($cv['description'] ?? '', 0, 120)) ?>…</td>
                  <td style="white-space:nowrap;">
                    <button type="button" onclick="cveDetails('<?= htmlspecialchars($cid) ?>')" class="btn" style="font-size:11px;padding:3px 8px;background:#e0e7ff;color:#3730a3;border:1px solid #c7d2fe;border-radius:5px;cursor:pointer;">Detay</button>
                    <?php if ($__cve_can_admin): ?>
                      <?php if ($is_dismissed): ?>
                        <button type="button" onclick="cveDismiss('<?= htmlspecialchars($cid) ?>', true)" class="btn" style="font-size:11px;padding:3px 8px;background:#fef3c7;color:#92400e;border:1px solid #fde68a;border-radius:5px;cursor:pointer;" title="Tekrar açıkla">↻</button>
                      <?php else: ?>
                        <button type="button" onclick="cveDismiss('<?= htmlspecialchars($cid) ?>', false)" class="btn" style="font-size:11px;padding:3px 8px;background:#fff;color:#64748b;border:1px solid var(--border);border-radius:5px;cursor:pointer;" title="Etkilenmiyoruz/yamalandı işaretle">✓</button>
                      <?php endif; ?>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </div>
    </div>

    <!-- Detail drawer -->
    <div id="cve-drawer-backdrop" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100;" onclick="cveDrawerClose()"></div>
    <div id="cve-drawer" style="display:none;position:fixed;top:0;right:0;width:min(640px,90vw);height:100vh;background:#fff;box-shadow:-4px 0 30px rgba(0,0,0,0.2);z-index:101;overflow-y:auto;padding:24px;">
      <button type="button" onclick="cveDrawerClose()" style="position:absolute;top:12px;right:12px;background:none;border:none;font-size:20px;cursor:pointer;color:var(--text-muted);">×</button>
      <div id="cve-drawer-content">Yükleniyor...</div>
    </div>

    <script>
    (function(){
      const CVES = <?= json_encode($__cves, JSON_UNESCAPED_UNICODE) ?>;
      function applyFilter(name){
        document.querySelectorAll('.cve-fchip').forEach(b => {
          b.style.background = b.dataset.filter === name ? '#0ea5e9' : '#fff';
          b.style.color = b.dataset.filter === name ? '#fff' : '#0f172a';
        });
        let shown = 0;
        document.querySelectorAll('.cve-row').forEach(r => {
          let visible = false;
          if (name === 'all') visible = true;
          else if (name === 'open') visible = r.classList.contains('cve-open');
          else if (name === 'kev') visible = r.classList.contains('cve-kev');
          else if (name === 'critical') visible = r.classList.contains('cve-critical');
          else if (name === 'dismissed') visible = r.classList.contains('cve-dismissed');
          r.style.display = visible ? '' : 'none';
          if (visible) shown++;
        });
        const b = document.getElementById('cve-count-badge');
        if (b) b.textContent = shown + ' görünür';
      }
      document.querySelectorAll('.cve-fchip').forEach(b => b.addEventListener('click', () => applyFilter(b.dataset.filter)));
      applyFilter('open');

      window.cveDetails = function(cid){
        const cv = CVES[cid]; if (!cv) return;
        const refs = (cv.references || []).map(u => `<li><a href="${u}" target="_blank" rel="noopener" style="color:#0ea5e9;word-break:break-all;">${u}</a></li>`).join('');
        const cwes = (cv.cwes || []).join(', ') || '-';
        const km = cv.kev_meta;
        document.getElementById('cve-drawer-content').innerHTML = `
          <h2 style="margin:0 0 8px;font-family:'Fira Code',monospace;font-size:18px;">${cid}</h2>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
            ${cv.cvss_score!==null?`<span style="background:${cv.cvss_score>=9?'#dc2626':cv.cvss_score>=7?'#f59e0b':cv.cvss_score>=4?'#0ea5e9':'#10b981'};color:#fff;padding:3px 10px;border-radius:4px;font-weight:700;font-size:12px;">CVSS ${cv.cvss_score}</span>`:''}
            ${cv.cvss_severity?`<span style="background:#e2e8f0;color:#475569;padding:3px 10px;border-radius:4px;font-size:11px;">${cv.cvss_severity}</span>`:''}
            ${cv.is_kev?`<span style="background:#dc2626;color:#fff;padding:3px 10px;border-radius:4px;font-weight:700;font-size:11px;">🚨 KEV</span>`:''}
            ${cv.matched_vendor?`<span style="background:#e0e7ff;color:#3730a3;padding:3px 10px;border-radius:4px;font-size:11px;">${cv.matched_vendor}</span>`:''}
            ${cv.dismissed_at?`<span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:4px;font-size:11px;">Dismissed: ${cv.dismissed_at} by ${cv.dismissed_by}</span>`:''}
          </div>
          <h3 style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px;">Açıklama</h3>
          <p style="font-size:13px;line-height:1.6;margin-bottom:16px;">${(cv.description||'').replace(/</g,'&lt;')}</p>
          ${km?`<h3 style="font-size:12px;color:#991b1b;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px;">CISA KEV</h3><ul style="font-size:12px;color:#475569;margin-bottom:16px;"><li><b>Vendor:</b> ${km.vendorProject||'-'} / ${km.product||'-'}</li><li><b>Eklendi:</b> ${km.dateAdded||'-'}</li><li><b>Due:</b> ${km.dueDate||'-'}</li><li><b>Ransomware:</b> ${km.knownRansomwareCampaignUse||'?'}</li><li><b>Action:</b> ${(km.shortDescription||'').replace(/</g,'&lt;')}</li></ul>`:''}
          <h3 style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px;">CWE</h3>
          <p style="font-size:12px;color:#475569;margin-bottom:16px;">${cwes}</p>
          <h3 style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px;">CVSS Vector</h3>
          <p style="font-size:11px;color:#475569;font-family:'Fira Code',monospace;margin-bottom:16px;">${cv.cvss_vector||'-'}</p>
          <h3 style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px;">References (${(cv.references||[]).length})</h3>
          <ul style="font-size:11px;padding-left:20px;">${refs||'<li>Yok</li>'}</ul>
          ${cv.dismissed_at&&cv.dismiss_note?`<h3 style="font-size:12px;color:#92400e;text-transform:uppercase;margin-top:16px;margin-bottom:6px;">Dismiss Notu</h3><p style="font-size:12px;color:#475569;background:#fef3c7;padding:8px;border-radius:6px;">${cv.dismiss_note.replace(/</g,'&lt;')}</p>`:''}
        `;
        document.getElementById('cve-drawer-backdrop').style.display='block';
        document.getElementById('cve-drawer').style.display='block';
      };
      window.cveDrawerClose = function(){
        document.getElementById('cve-drawer-backdrop').style.display='none';
        document.getElementById('cve-drawer').style.display='none';
      };
      window.cveDismiss = function(cid, undo){
        let note = '';
        if (!undo) {
          note = prompt('Dismiss notu (opsiyonel — neden etkilenmiyoruz/yamalandı):', '');
          if (note === null) return;
        }
        const fd = new URLSearchParams();
        fd.append('cve_id', cid);
        if (note) fd.append('note', note);
        if (undo) fd.append('undo', '1');
        fetch('/blacklist/cyberwebeyeos/cve_dismiss.php', {method:'POST', credentials:'same-origin', body:fd})
          .then(r=>r.json()).then(j=>{ if (j.ok) location.reload(); else alert('Hata: '+(j.error||'?')); });
      };
      window.cveSync = async function(){
        const out = document.getElementById('cve-sync-result');
        out.style.display='block'; out.textContent='⏳ NVD + KEV pull (~30 sn — anahtarsız)...';
        try {
          const r = await fetch('/blacklist/cyberwebeyeos/cve_fetch.php', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:''});
          const j = await r.json();
          out.textContent = JSON.stringify(j, null, 2);
          if (j.ok) setTimeout(()=>location.reload(), 1500);
        } catch(e) { out.textContent = '❌ ' + e.message; }
      };
    })();
    </script>
  </div>

  <!-- =================== TAB: STATUS / LOGS =================== -->
  <div class="tab-panel" id="tab-status">
<!-- SPRINT6-A1 START: Action Required widget -->
<section class="action-required" style="margin-bottom:24px;padding:16px;background:linear-gradient(135deg,#7f1d1d 0%,#450a0a 100%);border-radius:10px;border:1px solid #b91c1c;">
  <header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
    <h3 style="margin:0;color:#fecaca;">🚨 Action Required <span id="arCount" style="background:#dc2626;color:white;padding:2px 10px;border-radius:12px;font-size:13px;font-weight:700;">0</span></h3>
    <button onclick="arRefresh()" style="padding:6px 12px;background:rgba(255,255,255,0.1);color:#fecaca;border:1px solid #b91c1c;border-radius:6px;cursor:pointer;">↻ Refresh</button>
  </header>
  <div id="arList" style="display:flex;flex-direction:column;gap:8px;max-height:480px;overflow-y:auto;">
    <div style="color:#fca5a5;padding:12px;text-align:center;">Yükleniyor…</div>
  </div>
  <div id="arStats" style="margin-top:12px;padding-top:12px;border-top:1px solid #991b1b;color:#fecaca;font-size:12px;">
    <span id="arStatsText">…</span>
  </div>
</section>
<script>
async function arRefresh() {
  try {
    const [listResp, statsResp] = await Promise.all([
      fetch('cve_action.php?action=list').then(r=>r.json()),
      fetch('cve_action.php?action=stats').then(r=>r.json()),
    ]);
    document.getElementById('arCount').textContent = listResp.count || 0;
    document.getElementById('arStatsText').textContent =
      `Total ${statsResp.total||0} CVE · KEV ${statsResp.kev_count||0} · EPSS≥0.7 ${statsResp.epss_high_count||0}`;
    const ul = document.getElementById('arList');
    if (!listResp.items || listResp.items.length === 0) {
      ul.innerHTML = '<div style="color:#fca5a5;padding:12px;text-align:center;">✓ Aksiyon gereken CVE yok</div>';
      return;
    }
    ul.innerHTML = listResp.items.map(c => `
      <div style="padding:12px;background:rgba(0,0,0,0.3);border-radius:6px;display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center;">
        <div>
          <strong style="color:#fff;font-family:'Fira Code',monospace;">${c._id||c.id||''}</strong>
          ${c._kev_flag?'<span style="background:#dc2626;color:white;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px;">KEV</span>':''}
          ${c._pre_nvd?'<span style="background:#f59e0b;color:black;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px;">PSIRT-first</span>':''}
          ${c._customer_match?'<span style="background:#3b82f6;color:white;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px;">customer</span>':''}
        </div>
        <div style="color:#cbd5e1;font-size:12px;">
          ${(c.matched_vendor||'?').toUpperCase()} · CVSS ${c.cvss_score||'-'} · EPSS ${(c.epss_score||0).toFixed(2)}
          <div style="color:#94a3b8;margin-top:2px;">${(c.description||c.summary||'').substring(0,120)}</div>
        </div>
        <div style="display:flex;gap:6px;">
          <button onclick="arPivot('${c._id||c.id}')" style="padding:6px 10px;background:#0e7490;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;">🎯 IoC bul</button>
          <button onclick="arDismiss('${c._id||c.id}')" style="padding:6px 10px;background:#475569;color:white;border:none;border-radius:4px;cursor:pointer;font-size:12px;">Dismiss</button>
        </div>
      </div>`).join('');
  } catch(e){ console.error('arRefresh', e); }
}
async function arDismiss(cve) {
  if (!confirm('Dismiss ' + cve + '?')) return;
  const fd = new FormData(); fd.append('cve', cve);
  const r = await fetch('cve_action.php?action=dismiss', {method:'POST', body:fd});
  const j = await r.json();
  if (j.ok) arRefresh();
  else alert('Hata: ' + (j.error||'unknown'));
}
function arPivot(cve) {
  if (typeof iocPivotOpen === 'function') iocPivotOpen(cve);
  else alert('IoC pivot (Task A2) henüz yüklenmedi: ' + cve);
}
arRefresh();
setInterval(arRefresh, 300000); // 5 min auto-refresh
</script>
<!-- SPRINT6-A1 END -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" defer></script>
    <script>
    (function(){
      let loaded = false;
      window.cwe_load_dashboard = function(){
        if (loaded) return; loaded = true;
        fetch('/blacklist/cyberwebeyeos/dashboard_stats.php', {credentials:'same-origin'})
          .then(r => r.json()).then(d => {
            if (!d.ok) return;
            document.getElementById('dash-generated-at').textContent = d.generated_at;
            const t = d.totals || {};
            document.getElementById('t-bl').textContent = t.blacklist?.toLocaleString() ?? '-';
            document.getElementById('t-wl').textContent = t.whitelist?.toLocaleString() ?? '-';
            document.getElementById('t-pn').textContent = t.pending?.toLocaleString() ?? '-';
            document.getElementById('t-ex').textContent = t.expired?.toLocaleString() ?? '-';
            document.getElementById('t-fp').textContent = t.fp_reports?.toLocaleString() ?? '-';

            if (!window.Chart) { setTimeout(() => location.reload(), 800); return; }

            // 1. Trend line
            new Chart(document.getElementById('chart-trend'), {
              type:'line',
              data:{labels:d.trend_30d.map(x=>x.date.slice(5)),
                    datasets:[{label:'IoC eklendi', data:d.trend_30d.map(x=>x.count),
                               borderColor:'#16a085', backgroundColor:'rgba(22,160,133,.15)',
                               tension:.3, fill:true, pointRadius:2}]},
              options:{maintainAspectRatio:false, plugins:{legend:{display:false}},
                       scales:{y:{beginAtZero:true, ticks:{precision:0}}, x:{ticks:{maxRotation:0,autoSkip:true,maxTicksLimit:8}}}}
            });

            // 2. Type donut
            const typeColors = {'ip-src':'#10b981','ip-dst':'#059669','cidr':'#0ea5e9','ipv6':'#8b5cf6',
                                'domain':'#6366f1','hostname':'#6366f1','url':'#f59e0b',
                                'file-md5':'#ec4899','file-sha1':'#ec4899','file-sha256':'#ec4899','email-src':'#a855f7'};
            const typeLabels = Object.keys(d.type_distribution || {});
            const typeData = Object.values(d.type_distribution || {});
            new Chart(document.getElementById('chart-type'), {
              type:'doughnut',
              data:{labels:typeLabels, datasets:[{data:typeData,
                    backgroundColor:typeLabels.map(t => typeColors[t] || '#94a3b8'), borderWidth:0}]},
              options:{maintainAspectRatio:false, plugins:{legend:{position:'right',labels:{font:{size:10},boxWidth:10}}}}
            });

            // 3. TLP donut
            new Chart(document.getElementById('chart-tlp'), {
              type:'doughnut',
              data:{labels:['WHITE','GREEN','AMBER','RED'],
                    datasets:[{data:[d.tlp_distribution.WHITE,d.tlp_distribution.GREEN,d.tlp_distribution.AMBER,d.tlp_distribution.RED],
                               backgroundColor:['#e2e8f0','#10b981','#f59e0b','#dc2626'], borderWidth:0}]},
              options:{maintainAspectRatio:false, plugins:{legend:{position:'right',labels:{font:{size:11},boxWidth:12}}}}
            });

            // 4. Source bar
            const srcLabels = Object.keys(d.source_contribution || {});
            const srcData = Object.values(d.source_contribution || {});
            new Chart(document.getElementById('chart-source'), {
              type:'bar',
              data:{labels:srcLabels, datasets:[{label:'Adet', data:srcData,
                    backgroundColor:['#16a085','#6366f1','#f59e0b','#ec4899','#0ea5e9','#94a3b8']}]},
              options:{maintainAspectRatio:false, plugins:{legend:{display:false}},
                       scales:{y:{beginAtZero:true, ticks:{precision:0}}}}
            });
          })
          .catch(e => { document.getElementById('dash-generated-at').textContent = 'hata: ' + e.message; });
      };
      // Dashboard tab açıldığında yükle (R38 v2: ayrı tab)
      document.addEventListener('DOMContentLoaded', () => {
        const checkAndLoad = () => {
          const sp = document.getElementById('tab-dashboard');
          if (sp && sp.classList.contains('active')) window.cwe_load_dashboard();
        };
        checkAndLoad();
        document.querySelectorAll('.tab-btn[data-tab="dashboard"]').forEach(b =>
          b.addEventListener('click', () => setTimeout(window.cwe_load_dashboard, 50)));
      });
    })();
    </script>

    <?php
    // R33 (T2.3): Storage optimization widget (admin only)
    $__can_aggregate = (function_exists('cwe_current_role') && cwe_current_role() === 'admin');
    // R34 (T2.4): big tech whitelist sync widget
    $__bigtech_file = __DIR__ . '/bigtech_cidr.txt';
    $__bigtech_last_sync = file_exists($__bigtech_file) ? date('Y-m-d H:i:s', filemtime($__bigtech_file)) : null;
    $__bigtech_count = 0;
    if (file_exists($__bigtech_file)) {
        $__bigtech_count = (int)trim(shell_exec("grep -cv '^#' " . escapeshellarg($__bigtech_file)) ?: '0');
    }
    ?>
    <?php if ($__can_aggregate): ?>
    <div class="card" style="margin-bottom:18px;">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#dcfce7;color:#166534;"><i class="fas fa-cloud"></i></span> Big Tech Whitelist Sync</h2>
        <?php if ($__bigtech_last_sync): ?>
          <span class="badge badge-source"><?= htmlspecialchars($__bigtech_last_sync) ?> · <?= number_format($__bigtech_count) ?> CIDR</span>
        <?php else: ?>
          <span class="badge" style="background:#fef3c7;color:#92400e;">Henüz sync edilmedi</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">
          Google / Cloudflare / Microsoft / AWS'in resmi IP aralıkları haftalık olarak <code>bigtech_cidr.txt</code>'ye yazılır.
          Manuel ekleme sırasında çakışma varsa uyarı verilir (engellenmez).
          <br><b>Cron örneği:</b> <code>0 3 * * 0 php <?= __DIR__ ?>/bigtech_whitelist_sync.php --quiet</code>
        </p>
        <button type="button" onclick="bigtechSync()" class="btn btn-success" style="padding:7px 14px;font-size:12.5px;">
          <i class="fas fa-sync"></i> Şimdi Sync Et
        </button>
        <pre id="bigtech-result" style="display:none;background:var(--slate-50);padding:12px;border-radius:8px;font-size:11.5px;max-height:240px;overflow-y:auto;font-family:'Fira Code',monospace;margin-top:10px;"></pre>
      </div>
    </div>
    <script>
      window.bigtechSync = async function(){
        var out = document.getElementById('bigtech-result');
        out.style.display = 'block';
        out.textContent = '⏳ 4 sağlayıcıdan veri çekiliyor (ortalama 5-10 sn)...';
        try {
          var r = await fetch('/blacklist/cyberwebeyeos/bigtech_whitelist_sync.php', {
            method:'POST', credentials:'same-origin',
            headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: ''
          });
          var j = await r.json();
          out.textContent = JSON.stringify(j, null, 2);
          if (j.ok && j.total > 0) {
            setTimeout(() => { if (confirm('✅ Sync OK. Sayfayı yenile?')) location.reload(); }, 600);
          }
        } catch(e) { out.textContent = '❌ Hata: ' + e.message; }
      };
    </script>
    <?php endif; ?>
    <?php if ($__can_aggregate): ?>
    <!-- R41 (T4.1): Warninglist sources widget -->
    <div class="card" style="margin-bottom:18px;">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#fef3c7;color:#92400e;"><i class="fas fa-shield-alt"></i></span> Warninglists (FP Guard)</h2>
        <span class="badge badge-source">manuel + API + CSV ekleme öncesi kontrol</span>
      </div>
      <div class="card-body">
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:10px;">
          RFC1918 / IANA reserved / public DNS resolver / popüler domain'lerin blacklist'e eklenmesini engeller.
          Operatör <code>warninglist_override</code> ile bilinçli olarak geçebilir (audit log'da kayıt).
        </p>
        <table class="data-table" style="font-size:12px;margin-bottom:10px;">
          <thead><tr><th>Liste</th><th>Tip</th><th>Kayıt</th><th>Son güncelleme</th></tr></thead>
          <tbody>
          <?php
          $__wl_dir = __DIR__ . '/warninglists';
          if (is_dir($__wl_dir)) {
              foreach (glob($__wl_dir . '/*.txt') as $__wlf) {
                  $__name = basename($__wlf, '.txt');
                  $__count = 0;
                  foreach (file($__wlf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $__l) {
                      if ($__l !== '' && $__l[0] !== '#') $__count++;
                  }
                  $__mtime = file_exists($__wlf) ? date('Y-m-d H:i:s', filemtime($__wlf)) : '-';
                  $__type_label = match($__name) {
                      'rfc1918'         => 'CIDR (private)',
                      'iana_reserved'   => 'CIDR (reserved)',
                      'public_dns'      => 'IP (DNS)',
                      'popular_domains' => 'Domain (manual)',
                      'tranco_top'      => 'Domain (Tranco)',
                      default           => 'Karışık',
                  };
                  echo "<tr><td><b>{$__name}</b></td><td>{$__type_label}</td><td class='tabular mono'>{$__count}</td><td style='font-size:11px;color:#64748b;'>{$__mtime}</td></tr>";
              }
          }
          ?>
          </tbody>
        </table>
        <button type="button" onclick="warninglistSync()" class="btn btn-success" style="padding:6px 12px;font-size:12px;">
          <i class="fas fa-sync"></i> Tranco Şimdi Sync Et
        </button>
        <pre id="wl-result" style="display:none;background:var(--slate-50);padding:10px;border-radius:6px;font-size:11px;max-height:160px;overflow-y:auto;font-family:'Fira Code',monospace;margin-top:10px;"></pre>
        <div style="font-size:11px;color:var(--text-muted);margin-top:6px;">
          Cron: <code>0 2 * * 1 php <?= __DIR__ ?>/warninglist_sync.php --quiet</code>
        </div>
      </div>
    </div>
    <script>
    window.warninglistSync = async function(){
      var out = document.getElementById('wl-result');
      out.style.display = 'block';
      out.textContent = '⏳ Tranco top-10000 fetch ediliyor (~3 sn)...';
      try {
        var r = await fetch('/blacklist/cyberwebeyeos/warninglist_sync.php', {
          method:'POST', credentials:'same-origin',
          headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: 'top=10000'
        });
        var j = await r.json();
        out.textContent = JSON.stringify(j, null, 2);
      } catch(e) { out.textContent = '❌ ' + e.message; }
    };
    </script>

    <div class="card" style="margin-bottom:18px;">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#dbeafe;color:#1e40af;"><i class="fas fa-compress-arrows-alt"></i></span> Storage Optimization (CIDR Aggregation)</h2>
        <span class="badge badge-source">admin</span>
      </div>
      <div class="card-body">
        <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">
          Aynı /24 bloğunda <b id="cidr-threshold-display">50</b>+ tek IP varsa otomatik <code>x.y.z.0/24</code>'a indirgenir.
          Önce <b>Dry-Run</b> ile preview al, sonra uygula.
        </p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px;">
          <label style="font-size:12.5px;">Eşik:
            <input type="number" id="cidr-threshold" value="50" min="2" max="254"
                   style="width:70px;padding:6px 8px;border:1px solid var(--slate-300);border-radius:6px;margin-left:6px;font-family:inherit;"
                   oninput="document.getElementById('cidr-threshold-display').textContent=this.value;">
          </label>
          <button type="button" onclick="cidrAggregate(true)" class="btn btn-ghost" style="padding:7px 14px;font-size:12.5px;">
            <i class="fas fa-search"></i> Dry-Run (önizleme)
          </button>
          <button type="button" onclick="cidrAggregate(false)" class="btn btn-warning" style="padding:7px 14px;font-size:12.5px;">
            <i class="fas fa-compress-arrows-alt"></i> Şimdi Optimize Et
          </button>
        </div>
        <pre id="cidr-result" style="display:none;background:var(--slate-50);padding:12px;border-radius:8px;font-size:11.5px;max-height:240px;overflow-y:auto;font-family:'Fira Code',monospace;"></pre>
      </div>
    </div>
    <script>
      window.cidrAggregate = async function(dry){
        var th = parseInt(document.getElementById('cidr-threshold').value, 10) || 50;
        var out = document.getElementById('cidr-result');
        out.style.display = 'block';
        out.textContent = '⏳ ' + (dry ? 'Önizleme alınıyor...' : 'Uygulanıyor...');
        if (!dry && !confirm('⚠️ Bu işlem blacklist.txt\'i yeniden yazacak (backup alınır). Devam?')) {
          out.textContent = 'İptal edildi.'; return;
        }
        try {
          var body = 'threshold=' + th + (dry ? '&dry=1' : '');
          var r = await fetch('/blacklist/cyberwebeyeos/cidr_aggregate.php', {
            method:'POST', credentials:'same-origin',
            headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body: body
          });
          var j = await r.json();
          out.textContent = JSON.stringify(j, null, 2);
          if (j.ok && !dry && j.aggregated_count > 0) {
            setTimeout(() => { if (confirm('✅ Uygulandı. Sayfayı yenile?')) location.reload(); }, 500);
          }
        } catch(e) { out.textContent = '❌ Hata: ' + e.message; }
      };
    </script>
    <?php endif; ?>

    <?php
    // R32 (T2.2): Top FP Sources widget
    $__fp_data = @json_decode(@file_get_contents(__DIR__ . '/fp_state.json'), true);
    $__fp_sources = $__fp_data['source_counters'] ?? [];
    $__fp_top_iocs = $__fp_data['fp_state'] ?? [];
    if ($__fp_sources) {
        uasort($__fp_sources, fn($a,$b) => ($b['fp_total'] ?? 0) <=> ($a['fp_total'] ?? 0));
        $__fp_sources = array_slice($__fp_sources, 0, 10, true);
    }
    if ($__fp_top_iocs) {
        uasort($__fp_top_iocs, fn($a,$b) => ($b['fp_count'] ?? 0) <=> ($a['fp_count'] ?? 0));
        $__fp_top_iocs = array_slice($__fp_top_iocs, 0, 10, true);
    }
    $__fp_total = 0;
    foreach ($__fp_sources as $s) $__fp_total += $s['fp_total'] ?? 0;
    ?>
    <?php
    // R42 (T4.2): Sighting widget
    $__sight_data = @json_decode(@file_get_contents(__DIR__ . '/sighting_state.json'), true);
    $__sightings = $__sight_data['sightings'] ?? [];
    if ($__sightings) {
        uasort($__sightings, fn($a,$b) => ($b['count'] ?? 0) <=> ($a['count'] ?? 0));
        $__sightings_top = array_slice($__sightings, 0, 10, true);
    } else {
        $__sightings_top = [];
    }
    $__total_sightings = 0;
    foreach ($__sightings as $s) $__total_sightings += (int)($s['count'] ?? 0);
    ?>
    <div class="card" style="margin-bottom:18px;">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#dbeafe;color:#0c4a6e;"><i class="fas fa-eye"></i></span> Sighting Tracker</h2>
        <span class="badge badge-source">toplam <?= number_format($__total_sightings) ?> match · <?= count($__sightings) ?> unique IoC</span>
      </div>
      <div class="card-body">
        <?php if (empty($__sightings_top)): ?>
          <p style="font-size:13px;color:var(--text-muted);">Henüz sighting yok. SIEM'iniz IoC match event'lerini <code>/sighting.php</code>'a POST etmeli.</p>
        <?php else: ?>
          <table class="data-table" style="font-size:12px;margin-bottom:10px;">
            <thead><tr><th>IoC</th><th>Total</th><th>Sources</th><th>İlk</th><th>Son</th></tr></thead>
            <tbody>
              <?php foreach ($__sightings_top as $val => $info): ?>
                <tr>
                  <td style="font-family:'Fira Code',monospace;font-size:11px;"><?= htmlspecialchars($val) ?></td>
                  <td><span style="background:#0ea5e9;color:#fff;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;"><?= number_format((int)($info['count'] ?? 0)) ?></span></td>
                  <td style="font-size:11px;">
                    <?php foreach (($info['sources'] ?? []) as $src => $cnt): ?>
                      <span style="background:#e0e7ff;color:#3730a3;padding:1px 5px;border-radius:3px;font-size:10px;margin-right:2px;"><?= htmlspecialchars($src) ?>:<?= $cnt ?></span>
                    <?php endforeach; ?>
                  </td>
                  <td style="font-size:10.5px;color:#64748b;"><?= htmlspecialchars($info['first_seen'] ?? '-') ?></td>
                  <td style="font-size:10.5px;color:#64748b;"><?= htmlspecialchars($info['last_seen'] ?? '-') ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
        <details style="margin-top:10px;font-size:11.5px;color:var(--text-muted);">
          <summary style="cursor:pointer;">📡 SIEM entegrasyon notu</summary>
          <div style="padding:10px;background:var(--slate-50);border-radius:6px;margin-top:6px;">
            <p>SIEM **sadece IoC match event'lerini** buraya POST etmeli — ham firewall event'leri gönderme (DB şişer).</p>
            <p style="margin-top:8px;"><b>Endpoint:</b> <code>POST /blacklist/cyberwebeyeos/sighting.php</code></p>
            <p><b>Auth:</b> <code>X-API-Key: &lt;key&gt;</code></p>
            <p><b>Single:</b></p>
            <pre style="background:#fff;padding:8px;border-radius:4px;font-size:10.5px;overflow:auto;">{"value":"1.2.3.4","source":"wazuh","observed_at":"2026-05-21 13:00:00","count":1}</pre>
            <p><b>Batch:</b></p>
            <pre style="background:#fff;padding:8px;border-radius:4px;font-size:10.5px;overflow:auto;">{"sightings":[{"value":"1.2.3.4","source":"wazuh","count":3},{"value":"evil.com","source":"wazuh","count":1}]}</pre>
            <p><b>Wazuh integrator örneği</b> (<code>/var/ossec/etc/ossec.conf</code>):</p>
            <pre style="background:#fff;padding:8px;border-radius:4px;font-size:10.5px;overflow:auto;">&lt;integration&gt;
  &lt;name&gt;custom-cwe-sighting&lt;/name&gt;
  &lt;hook_url&gt;https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos/sighting.php&lt;/hook_url&gt;
  &lt;api_key&gt;cwe_xxx&lt;/api_key&gt;
  &lt;rule_id&gt;100100&lt;/rule_id&gt;  &lt;!-- sadece "IoC match" rule'u --&gt;
  &lt;alert_format&gt;json&lt;/alert_format&gt;
&lt;/integration&gt;</pre>
            <p>Rate limit: 100 req / 10s per key. Toplu batch tercih edilir.</p>
          </div>
        </details>
      </div>
    </div>

    <?php
    // R44 (T4.4): Source Reliability Score
    // - Source attribution: blacklist.txt added_by + ./_dyn/*.txt (external feeds)
    // - FP rate: fp_state.source_counters / total contributed
    // - Score: (1 - fp_rate) * 100 — yüksek = güvenilir
    $__src_totals = []; // source_label → count
    if (file_exists(__DIR__ . '/blacklist.txt')) {
        foreach (file(__DIR__ . '/blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if ($line === '' || $line[0] === '#') continue;
            $e = cwe_parse_blacklist_entry($line);
            $ab = $e['added_by'];
            if ($ab === 'legacy') $key = 'legacy';
            elseif (str_starts_with($ab, 'api:')) $key = 'api';
            elseif (str_starts_with($ab, 'csv:')) $key = 'csv-import';
            elseif (str_starts_with($ab, 'cidr-aggregate')) $key = 'aggregate';
            else $key = 'manual:' . $ab;
            $__src_totals[$key] = ($__src_totals[$key] ?? 0) + 1;
        }
    }
    // External feed counts (sources_config.json output_file satır sayısı)
    $__src_cfg = @json_decode(@file_get_contents(__DIR__ . '/sources_config.json'), true);
    foreach (($__src_cfg['sources'] ?? []) as $src) {
        $of = $src['output_file'] ?? '';
        if ($of && file_exists($of)) {
            $cnt = 0;
            foreach (file($of, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ll) {
                if ($ll !== '' && $ll[0] !== '#') $cnt++;
            }
            $__src_totals['feed:' . ($src['id'] ?? $src['name'] ?? '?')] = $cnt;
        }
    }
    // FP per source (fp_state.source_counters)
    $__src_fp = $__fp_data['source_counters'] ?? [];
    // Build ranking
    $__src_rows = [];
    foreach ($__src_totals as $name => $total) {
        $fp = (int)($__src_fp[$name]['fp_total'] ?? 0);
        $fp_rate = $total > 0 ? ($fp / $total) : 0;
        $score = $total > 0 ? round((1 - $fp_rate) * 100, 1) : null;
        $default_conf = null;
        // Match source confidence from sources_config
        foreach (($__src_cfg['sources'] ?? []) as $src) {
            if (str_starts_with($name, 'feed:') && (($src['id'] ?? '') === substr($name, 5) || ($src['name'] ?? '') === substr($name, 5))) {
                $default_conf = $src['default_confidence'] ?? null;
                break;
            }
        }
        $__src_rows[] = [
            'name' => $name,
            'total' => $total,
            'fp' => $fp,
            'fp_rate' => $fp_rate,
            'score' => $score,
            'default_confidence' => $default_conf,
            'last_fp' => $__src_fp[$name]['last_fp'] ?? null,
        ];
    }
    usort($__src_rows, fn($a,$b) => $b['total'] <=> $a['total']);
    ?>
    <?php if (!empty($__src_rows)): ?>
    <div class="card" style="margin-bottom:18px;">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#dcfce7;color:#166534;"><i class="fas fa-balance-scale"></i></span> Source Reliability Score</h2>
        <span class="badge badge-source">FP rate düşük = güvenilir kaynak</span>
      </div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="data-table" style="font-size:12px;">
            <thead><tr>
              <th>Kaynak</th>
              <th class="tabular">IoC sayısı</th>
              <th class="tabular">FP rapor</th>
              <th class="tabular">FP oranı</th>
              <th>Reliability</th>
              <th>Default Conf</th>
              <th>Son FP</th>
            </tr></thead>
            <tbody>
              <?php foreach ($__src_rows as $r):
                $score = $r['score'];
                $color = is_null($score) ? '#94a3b8'
                       : ($score >= 95 ? '#10b981' : ($score >= 85 ? '#0ea5e9' : ($score >= 60 ? '#f59e0b' : '#dc2626')));
              ?>
              <tr>
                <td style="font-family:'Fira Code',monospace;font-size:11.5px;"><?= htmlspecialchars($r['name']) ?></td>
                <td class="tabular mono"><?= number_format($r['total']) ?></td>
                <td class="tabular mono"><?= $r['fp'] ?></td>
                <td class="tabular mono"><?= number_format($r['fp_rate'] * 100, 2) ?>%</td>
                <td>
                  <?php if (!is_null($score)): ?>
                    <span style="display:inline-flex;align-items:center;gap:4px;">
                      <span style="width:80px;height:8px;background:var(--slate-100);border-radius:4px;overflow:hidden;">
                        <span style="display:block;height:100%;width:<?= $score ?>%;background:<?= $color ?>;"></span>
                      </span>
                      <span style="font-family:'Fira Code',monospace;font-size:11px;color:<?= $color ?>;font-weight:700;"><?= $score ?></span>
                    </span>
                  <?php else: ?>
                    <span style="color:#94a3b8;font-size:11px;">—</span>
                  <?php endif; ?>
                </td>
                <td>
                  <?php if (!is_null($r['default_confidence'])): ?>
                    <span style="font-family:'Fira Code',monospace;color:<?= cwe_confidence_color((int)$r['default_confidence']) ?>;font-weight:700;font-size:11.5px;"><?= (int)$r['default_confidence'] ?></span>
                  <?php else: ?>
                    <span style="color:#94a3b8;font-size:11px;">—</span>
                  <?php endif; ?>
                </td>
                <td style="font-size:10.5px;color:#64748b;"><?= htmlspecialchars($r['last_fp'] ?? '-') ?></td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:8px;">
          ℹ️ <b>Reliability</b> = (1 - FP oranı) × 100. 95+ ideal, &lt;60 gözden geçirilmeli.
          <b>Default Conf</b> kaynak admin tarafından atanır (T2.5).
        </div>
      </div>
    </div>
    <?php endif; ?>

    <?php if ($__fp_total > 0): ?>
    <div class="card" style="margin-bottom:18px;">
      <div class="card-head">
        <h2><span class="h2-icon" style="background:#fef3c7;color:#92400e;"><i class="fas fa-flag"></i></span> False Positive İstatistikleri</h2>
        <span class="badge badge-source">toplam <?= (int)$__fp_total ?> FP</span>
      </div>
      <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr;gap:18px;">
        <div>
          <h3 style="font-size:13px;color:var(--text-muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.04em;">Top FP Kaynakları</h3>
          <table class="data-table" style="font-size:12px;">
            <thead><tr><th>Kaynak</th><th>FP</th><th>Son FP</th></tr></thead>
            <tbody>
              <?php foreach ($__fp_sources as $src => $info): ?>
                <tr>
                  <td style="font-family:'Fira Code',monospace;font-size:11px;"><?= htmlspecialchars($src) ?></td>
                  <td><span style="background:#dc2626;color:#fff;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;"><?= (int)($info['fp_total'] ?? 0) ?></span></td>
                  <td style="font-size:11px;color:#64748b;"><?= htmlspecialchars($info['last_fp'] ?? '-') ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        <div>
          <h3 style="font-size:13px;color:var(--text-muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.04em;">En Çok Raporlanan IoC'ler</h3>
          <table class="data-table" style="font-size:12px;">
            <thead><tr><th>IoC</th><th>FP</th><th>Son</th></tr></thead>
            <tbody>
              <?php foreach ($__fp_top_iocs as $val => $info): ?>
                <tr>
                  <td style="font-family:'Fira Code',monospace;font-size:11px;"><?= htmlspecialchars($val) ?></td>
                  <td><span style="background:#dc2626;color:#fff;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;"><?= (int)($info['fp_count'] ?? 0) ?></span></td>
                  <td style="font-size:11px;color:#64748b;"><?= htmlspecialchars($info['last_fp_report'] ?? '-') ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
          <div style="margin-top:8px;font-size:11px;color:var(--text-muted);">
            ℹ️ 3+ FP rapor alan IoC otomatik pending'e taşınır.
          </div>
        </div>
      </div>
    </div>
    <?php endif; ?>

    <div class="main-grid">
      <section>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon brand"><i class="fas fa-shield-alt"></i></span> Audit Log (Son İşlemler)</h2>
            <span class="badge badge-source">son 50 kayıt</span>
          </div>
          <div class="card-body flush">
            <?php
            $audit_events = audit_log_recent(50);
            $audit_summary = audit_log_summary();
            ?>
            <?php if (empty($audit_events)): ?>
              <div class="empty" style="padding:32px 16px;">
                <div class="empty-icon muted"><i class="fas fa-shield-alt"></i></div>
                <div class="empty-title">Audit kaydı yok</div>
                <div class="empty-desc">İşlem yaptığında değişiklikler burada loglanacak.</div>
              </div>
            <?php else: ?>
              <div class="table-responsive">
                <table class="data-table">
                  <thead><tr><th>Zaman</th><th>Kullanıcı</th><th>Aksiyon</th><th>Detay</th><th>IP</th></tr></thead>
                  <tbody>
                  <?php foreach ($audit_events as $e):
                    $action = $e['action'] ?? '-';
                    $color = strpos($action,'delete')!==false?'badge-pending':(strpos($action,'add')!==false||strpos($action,'create')!==false?'badge-whitelist':'badge-manual');
                  ?>
                    <tr>
                      <td class="mono" style="font-size:11.5px;color:var(--text-muted);"><?= htmlspecialchars($e['ts'] ?? '-') ?></td>
                      <td><span class="badge badge-manual"><?= htmlspecialchars($e['user'] ?? '-') ?></span></td>
                      <td><span class="badge <?= $color ?>"><?= htmlspecialchars($action) ?></span></td>
                      <td class="mono" style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars(substr(json_encode($e['details'] ?? [], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES), 0, 80)) ?></td>
                      <td class="mono" style="font-size:11px;"><?= htmlspecialchars($e['ip'] ?? '-') ?></td>
                    </tr>
                  <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php endif; ?>
          </div>
        </div>

        <?php if (!empty($recent_logs)): ?>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon slate"><i class="fas fa-file-alt"></i></span> Fetch Logları (ip_blocklist.log)</h2>
          </div>
          <div class="card-body">
            <div class="log-list">
              <?php foreach ($recent_logs as $line): ?><div class="log-line"><?= htmlspecialchars($line) ?></div><?php endforeach; ?>
            </div>
          </div>
        </div>
        <?php endif; ?>

        <?php if (!empty($conflict_logs)): ?>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon amber"><i class="fas fa-exclamation-triangle"></i></span> Çakışma Logları</h2>
          </div>
          <div class="card-body">
            <div class="log-list">
              <?php foreach ($conflict_logs as $line): ?>
                <div class="log-line"><?= htmlspecialchars($line) ?></div>
              <?php endforeach; ?>
            </div>
          </div>
        </div>
        <?php endif; ?>
      </section>

      <aside>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon green"><i class="fas fa-server"></i></span> Sistem Durumu</h2>
          </div>
          <div class="card-body" style="font-size:13px;line-height:1.8;">
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">PHP</span>
              <span class="mono"><?= phpversion() ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">Server</span>
              <span class="mono"><?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? '-') ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">Manuel</span>
              <span class="mono tabular"><?= $manual_count ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">Birleşik Feed</span>
              <span class="mono tabular"><?= $feed_count ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;border-bottom:1px solid var(--slate-100);padding:4px 0;">
              <span style="color:var(--text-muted);">USOM</span>
              <span class="mono tabular"><?= number_format($usom_total, 0, ',', '.') ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:4px 0;">
              <span style="color:var(--text-muted);">Pending</span>
              <span class="mono tabular"><?= $pending_count ?></span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon brand"><i class="fas fa-link"></i></span> Hızlı Linkler</h2>
          </div>
          <div class="nav-list">
            <a href="cyberwebeyeosblacklist.txt" target="_blank"><i class="fas fa-file-alt nav-icon"></i> Cyberwebeyeos Feed</a>
            <a href="/blacklist/usom/url-list.txt" target="_blank"><i class="fas fa-file-alt nav-icon"></i> USOM Combined</a>
            <a href="/blacklist/usom/domain-list.txt" target="_blank"><i class="fas fa-file-alt nav-icon"></i> USOM Domain</a>
            <a href="/blacklist/usom/ip-list.txt" target="_blank"><i class="fas fa-file-alt nav-icon"></i> USOM IPv4</a>
          </div>
        </div>

        <?php $ncfg = @json_decode(@file_get_contents(__DIR__ . '/notifications.json'), true) ?: []; ?>
        <div class="card">
          <div class="card-head">
            <h2><span class="h2-icon amber"><i class="fas fa-bell"></i></span> Bildirimler</h2>
            <span class="badge <?= (!empty($ncfg['email']['enabled']) || !empty($ncfg['webhook']['enabled'])) ? 'badge-whitelist' : 'badge-source' ?>">
              <?= (!empty($ncfg['email']['enabled']) || !empty($ncfg['webhook']['enabled'])) ? 'Aktif' : 'Pasif' ?>
            </span>
          </div>
          <div class="card-body">
            <form method="post" action="notify.php">
              <input type="hidden" name="save_settings" value="1">
              <div class="field" style="display:flex;align-items:center;gap:8px;"><input type="checkbox" name="email_enabled" id="ne" <?= !empty($ncfg['email']['enabled']) ? 'checked' : '' ?> style="width:auto;"><label for="ne" style="margin:0;">Email aktif</label></div>
              <div class="field"><label>Email alıcı</label><input type="email" name="email_to" value="<?= htmlspecialchars($ncfg['email']['to'] ?? '') ?>" placeholder="admin@example.com"></div>
              <div class="field"><label>Email gönderen</label><input type="email" name="email_from" value="<?= htmlspecialchars($ncfg['email']['from'] ?? '') ?>"></div>
              <div class="field"><label>Gönderen adı</label><input type="text" name="email_from_name" value="<?= htmlspecialchars($ncfg['email']['from_name'] ?? 'Cyberwebeyeos TIP') ?>"></div>

              <!-- R36 (T3.1): SMTP fields -->
              <details style="margin:6px 0 8px;">
                <summary style="cursor:pointer;color:var(--text-muted);font-size:12px;">⚙️ SMTP Ayarları (opsiyonel — yoksa PHP mail())</summary>
                <div style="padding:8px 4px;border-left:2px solid var(--brand-300);margin-top:6px;padding-left:10px;">
                  <div class="field" style="display:flex;align-items:center;gap:8px;"><input type="checkbox" name="smtp_enabled" id="se" <?= !empty($ncfg['smtp']['enabled']) ? 'checked' : '' ?> style="width:auto;"><label for="se" style="margin:0;">SMTP aktif (mail() yerine kullan)</label></div>
                  <div class="field"><label>Host</label><input type="text" name="smtp_host" value="<?= htmlspecialchars($ncfg['smtp']['host'] ?? '') ?>" placeholder="smtp.gmail.com / smtp.office365.com"></div>
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                    <div class="field"><label>Port</label><input type="number" name="smtp_port" value="<?= (int)($ncfg['smtp']['port'] ?? 587) ?>" min="1" max="65535"></div>
                    <div class="field"><label>Şifreleme</label>
                      <select name="smtp_encryption">
                        <option value="tls" <?= ($ncfg['smtp']['encryption'] ?? 'tls')==='tls'?'selected':'' ?>>TLS (587, STARTTLS)</option>
                        <option value="ssl" <?= ($ncfg['smtp']['encryption'] ?? '')==='ssl'?'selected':'' ?>>SSL (465, SMTPS)</option>
                        <option value="none" <?= ($ncfg['smtp']['encryption'] ?? '')==='none'?'selected':'' ?>>None (25, plain)</option>
                      </select>
                    </div>
                  </div>
                  <div class="field"><label>Kullanıcı</label><input type="text" name="smtp_username" value="<?= htmlspecialchars($ncfg['smtp']['username'] ?? '') ?>" autocomplete="off"></div>
                  <div class="field"><label>Parola <span style="font-size:11px;color:var(--text-muted);">(boş bırakırsan mevcut korunur)</span></label><input type="password" name="smtp_password" value="" autocomplete="new-password" placeholder="<?= !empty($ncfg['smtp']['password']) ? '••••••• (mevcut)' : '' ?>"></div>
                </div>
              </details>

              <div class="field" style="display:flex;align-items:center;gap:8px;"><input type="checkbox" name="webhook_enabled" id="nw" <?= !empty($ncfg['webhook']['enabled']) ? 'checked' : '' ?> style="width:auto;"><label for="nw" style="margin:0;">Webhook aktif</label></div>
              <div class="field"><label>Webhook URL (Slack/Discord/custom)</label><input type="url" name="webhook_url" value="<?= htmlspecialchars($ncfg['webhook']['url'] ?? '') ?>" placeholder="https://hooks.slack.com/..."></div>

              <!-- R37 (T3.2): Syslog forwarder (Wazuh/Splunk/QRadar) -->
              <div class="field" style="display:flex;align-items:center;gap:8px;"><input type="checkbox" name="syslog_enabled" id="sy" <?= !empty($ncfg['syslog']['enabled']) ? 'checked' : '' ?> style="width:auto;"><label for="sy" style="margin:0;">Syslog aktif (yerel syslogd'a forward)</label></div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                <div class="field"><label>Facility</label>
                  <select name="syslog_facility">
                    <?php $__sf = $ncfg['syslog']['facility'] ?? 'local0'; foreach (['local0','local1','local2','local3','local4','local5','local6','local7','user','daemon'] as $__f): ?>
                      <option value="<?= $__f ?>" <?= $__sf===$__f?'selected':'' ?>><?= $__f ?></option>
                    <?php endforeach; ?>
                  </select>
                </div>
                <div class="field"><label>Ident (program adı)</label><input type="text" name="syslog_ident" value="<?= htmlspecialchars($ncfg['syslog']['ident'] ?? 'cyberwebeyeos-tip') ?>"></div>
              </div>
              <div class="field-help" style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">
                Her audit event JSON formatında <code>syslog(LOG_NOTICE)</code>'a yazılır.
                Wazuh/Splunk universal forwarder <code>/var/log/syslog</code> tail'leyerek consume eder.
                rsyslog config: <code>local0.* /var/log/cyberwebeyeos.log</code>
              </div>
              <details style="margin-top:8px;font-size:12px;"><summary style="cursor:pointer;color:var(--text-muted);">Hangi event'lerde bildir</summary>
                <?php foreach (['blacklist_add','blacklist_delete','whitelist_add','user_create','user_delete','user_password_change','source_fetch_failed','csv_import','api_ingest'] as $e): ?>
                  <div style="margin:4px 0;display:flex;align-items:center;gap:6px;"><input type="checkbox" name="event_<?= $e ?>" id="ev_<?= $e ?>" <?= !empty($ncfg['events'][$e]) ? 'checked' : '' ?> style="width:auto;"><label for="ev_<?= $e ?>" style="margin:0;font-size:12px;"><?= $e ?></label></div>
                <?php endforeach; ?>
              </details>
              <div style="display:flex;gap:6px;margin-top:10px;">
                <button type="submit" class="btn btn-primary btn-sm" style="flex:1;"><i class="fas fa-save"></i> Kaydet</button>
              </div>
            </form>
            <form method="post" action="notify.php" style="margin-top:6px;">
              <input type="hidden" name="test_notification" value="1">
              <button type="submit" class="btn btn-ghost btn-sm btn-block"><i class="fas fa-paper-plane"></i> Test Bildirimi Gönder</button>
            </form>
          </div>
        </div>
      </aside>
    </div>
  </div>

</div>

<footer class="footer">
  © <?= date('Y') ?> Cyberwebeyeos &middot; Threat Intelligence Platform
  &nbsp;·&nbsp; <a href="logout.php">Çıkış Yap</a>
</footer>

<script>
  // ===== TAB ROUTING (R88d: query string-only, hash kaldırıldı) =====
  const tabs = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.tab-panel');
  function showTab(name, pushUrl) {
    if (pushUrl === undefined) pushUrl = true;
    tabs.forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    panels.forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
    document.body.dataset.tab = name;  // R91c: CSS body[data-tab="..."] selector için (full-viewport blacklist)
    if (pushUrl) {
      try {
        var url = new URL(window.location.href);
        // R91h: tab=blacklist URL'de görünsün (R89f tersi)
        if (name === 'blacklist') {
          url.searchParams.set('tab', 'blacklist');  // R91h: URL'de görünsün
          // R91g: page=1 explicit default (URL'de görünsün)
          if (!url.searchParams.has('page')) {
            url.searchParams.set('page', '1');
          }
        } else {
          url.searchParams.set('tab', name);
        }
        // R91e: kalıcı çözüm — sadece 'tab' param izin ver, geri kalanını sil
        if (name !== 'blacklist') {
          var allowedParams = ['tab'];
          var allKeys = Array.from(url.searchParams.keys());
          allKeys.forEach(function(k) {
            if (allowedParams.indexOf(k) === -1) url.searchParams.delete(k);
          });
        }
        // Hash'i HER ZAMAN temizle (legacy birikinti olmasın)
        var newUrl = url.pathname + (url.search || '');
        history.pushState({}, '', newUrl);
      } catch(e) { console.warn('[R88d] pushState fail:', e); }
    }
    window.scrollTo({top: 0, behavior:'smooth'});
  }
  // Expose for inline onclick handlers
  window.showTab = showTab;
  tabs.forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  document.querySelectorAll('[data-jump]').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', () => showTab(el.dataset.jump));
  });
  // R88d: Initial tab — query string > hash (backward compat) > default
  (function(){
    var params = new URLSearchParams(window.location.search);
    // R89e: ?list= varsa default tab=blacklist (URL tutarliligi)
    var initTab = params.get('tab') || (params.get('list') || params.get('page') ? 'blacklist' : '') || location.hash.replace('#','').split('/')[0] || '';
    if (initTab && document.getElementById('tab-' + initTab)) {
      // R89f: default tab (blacklist) URL'i temiz biraksin (pushState YOK)
      showTab(initTab, /*pushUrl=*/ initTab !== 'blacklist');
    } else {
      document.body.dataset.tab = 'blacklist';  // R91c: default tab init için body data attribute
    }
    if (!initTab && location.hash) {
      // Hash hâlâ varsa temizle (initTab geçersizdi)
      history.replaceState({}, '', window.location.pathname + window.location.search);
    }
    // R91h: sayfa açılışında blacklist default ise tab=blacklist&page=1 ekle (URL'de görünsün)
    try {
      var _initParams = new URLSearchParams(window.location.search);
      var _curTab = _initParams.get('tab');
      if ((!_curTab || _curTab === 'blacklist') && (!_initParams.get('page') || _curTab !== 'blacklist')) {
        if (!_initParams.get('page')) _initParams.set('page', '1');
        _initParams.set('tab', 'blacklist');  // R91h: URL'de görünsün
        var _newSearch = _initParams.toString();
        history.replaceState({}, '', window.location.pathname + (_newSearch ? '?' + _newSearch : ''));
      }
    } catch(e) {}
  })();
  // R88d: popstate — back/forward navigation
  window.addEventListener('popstate', function() {
    var params = new URLSearchParams(window.location.search);
    var tab = params.get('tab') || 'blacklist';
    if (document.getElementById('tab-' + tab)) {
      showTab(tab, /*pushUrl=*/ false); // popstate'de pushState yapma (loop önle)
    }
  });
  // R88d: <a href="?tab=..."> empty-state link'ler — reload yerine showTab
  document.querySelectorAll('a[href^="?tab="]').forEach(function(a){
    a.addEventListener('click', function(e){
      e.preventDefault();
      var params = new URLSearchParams(a.getAttribute('href').replace(/^\?/, ''));
      var tab = params.get('tab');
      if (tab) showTab(tab);
    });
  });

  // ===== GLOBAL SEARCH =====
  (function(){
    const inp = document.getElementById('global-search');
    const box = document.getElementById('global-search-results');
    if (!inp || !box) return;
    let t = null;
    inp.addEventListener('input', () => {
      clearTimeout(t);
      const q = inp.value.trim();
      if (q.length < 2) { box.style.display = 'none'; return; }
      t = setTimeout(async () => {
        try {
          const r = await fetch('search.php?q=' + encodeURIComponent(q));
          const j = await r.json();
          if (!j.results || j.results.length === 0) {
            box.innerHTML = '<div style="padding:14px;color:var(--text-muted);font-size:12px;text-align:center;">Sonuç yok</div>';
          } else {
            box.innerHTML = j.results.map(x => `
              <div onclick="showTab('${x.tab}');this.parentElement.style.display='none';" style="padding:10px 14px;border-bottom:1px solid var(--slate-100);cursor:pointer;display:flex;justify-content:space-between;gap:10px;align-items:center;font-size:12.5px;" onmouseover="this.style.background='var(--brand-50)'" onmouseout="this.style.background=''">
                <div style="flex:1;min-width:0;">
                  <div class="mono" style="color:var(--text);word-break:break-all;">${x.value.replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</div>
                  ${x.extra ? `<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${x.extra.replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</div>` : ''}
                </div>
                <span class="badge badge-source" style="font-size:10px;">${x.source}</span>
              </div>`).join('');
          }
          box.style.display = 'block';
        } catch (e) { box.innerHTML = '<div style="padding:10px;color:var(--danger);">Arama hatası</div>'; box.style.display = 'block'; }
      }, 250);
    });
    document.addEventListener('click', (e) => {
      if (!box.contains(e.target) && e.target !== inp) box.style.display = 'none';
    });
    // Ctrl+K shortcut
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault(); inp.focus(); inp.select();
      }
    });
  })();

  // ===== TOAST AUTO-DISMISS =====
  document.querySelectorAll('.toast.success, .toast.info').forEach(t => {
    setTimeout(() => { t.style.transition = 'opacity .25s'; t.style.opacity = '0';
                       setTimeout(() => t.remove(), 250); }, 5000);
  });

  // ===== USOM Schedule Editor =====
  const usomFullType = document.getElementById('usom-full-type');
  if (usomFullType) {
    function usomToggleFullPeriod() {
      const t = usomFullType.value;
      const dom = document.getElementById('usom-full-dom-field');
      const dow = document.getElementById('usom-full-dow-field');
      if (dom && dow) {
        dom.style.display = t === 'monthly' ? '' : 'none';
        dow.style.display = t === 'weekly'  ? '' : 'none';
      }
    }
    usomFullType.addEventListener('change', usomToggleFullPeriod);
    usomToggleFullPeriod();

    // Day & hour chip toggles
    document.querySelectorAll('#usom-inc-days .badge[data-day]').forEach(c => {
      c.addEventListener('click', () => {
        const on = c.classList.toggle('badge-manual');
        c.classList.toggle('badge-source', !on);
        c.style.border = on ? '1px solid var(--brand-500)' : '';
      });
    });
    document.querySelectorAll('#usom-inc-hours .badge[data-hour]').forEach(c => {
      c.addEventListener('click', () => {
        const on = c.classList.toggle('badge-manual');
        c.classList.toggle('badge-source', !on);
        c.style.border = on ? '1px solid var(--brand-500)' : '';
      });
    });

    function usomCollectSchedule() {
      const [fh, fm] = (document.getElementById('usom-full-time').value || '01:00').split(':').map(n => parseInt(n,10) || 0);
      return {
        full: {
          enabled: document.getElementById('usom-full-enabled').checked,
          type: usomFullType.value,
          day_of_month: parseInt(document.getElementById('usom-full-dom').value, 10),
          day_of_week:  parseInt(document.getElementById('usom-full-dow').value, 10),
          hour: fh, minute: fm,
        },
        incremental: {
          enabled: document.getElementById('usom-inc-enabled').checked,
          days:  Array.from(document.querySelectorAll('#usom-inc-days .badge.badge-manual')).map(c => parseInt(c.dataset.day, 10)),
          hours: Array.from(document.querySelectorAll('#usom-inc-hours .badge.badge-manual')).map(c => parseInt(c.dataset.hour, 10)),
          minute: parseInt(document.getElementById('usom-inc-minute').value, 10) || 0,
        },
      };
    }

    function usomMsg(text, kind) {
      const m = document.getElementById('usom-sch-msg');
      if (!m) return;
      m.style.display = 'block';
      m.style.padding = '8px 12px';
      m.style.borderRadius = '6px';
      const colors = { ok: ['#d1fae5','#065f46'], err: ['#fee2e2','#991b1b'], info: ['#dbeafe','#1e40af'] };
      const [bg, fg] = colors[kind] || colors.info;
      m.style.background = bg; m.style.color = fg;
      m.textContent = text;
      if (kind !== 'info') setTimeout(() => { m.style.display = 'none'; }, 4000);
    }

    document.getElementById('usom-save-sch')?.addEventListener('click', async () => {
      const s = usomCollectSchedule();
      if (s.incremental.enabled && (s.incremental.days.length === 0 || s.incremental.hours.length === 0)) {
        usomMsg('Artımlı sync için en az bir gün ve bir saat seçmelisin.', 'err');
        return;
      }
      try {
        const r = await fetch('/blacklist/usom/schedule.php?action=save', {
          method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(s),
        });
        const j = await r.json();
        usomMsg(j.ok ? 'Zamanlama kaydedildi.' : 'Hata: ' + (j.error || 'bilinmeyen'), j.ok ? 'ok' : 'err');
      } catch (e) { usomMsg('Bağlantı hatası: ' + e.message, 'err'); }
    });

    async function usomRun(full) {
      if (!confirm(full ? 'Tam sync ~20 dakika sürer. Başlatılsın mı?' : 'Artımlı sync başlatılsın mı?')) return;
      usomMsg('Sync başlatılıyor…', 'info');
      try {
        const r = await fetch('/blacklist/usom/schedule.php?action=run', {
          method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({full}),
        });
        const j = await r.json();
        if (j.ok) { usomMsg('Sync arka planda başlatıldı. ~30 sn sonra sayfayı yenile.', 'ok'); }
        else { usomMsg('Hata: ' + (j.error || 'bilinmeyen'), 'err'); }
      } catch (e) { usomMsg('Bağlantı hatası: ' + e.message, 'err'); }
    }
    document.getElementById('usom-run-full')?.addEventListener('click', () => usomRun(true));
    document.getElementById('usom-run-inc') ?.addEventListener('click', () => usomRun(false));
  }
</script>

  </div><!-- /main-pane -->
</div><!-- /app-shell -->

<!-- R48 (T5.3): Keyboard shortcuts + help overlay -->
<div id="kb-help-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:300;" onclick="document.getElementById('kb-help-bg').style.display='none';"></div>
<div id="kb-help" style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#fff;border-radius:14px;padding:24px;min-width:380px;max-width:520px;z-index:301;box-shadow:0 20px 60px rgba(0,0,0,.3);font-size:13px;">
  <h2 style="margin:0 0 16px;font-size:16px;">⌨ Klavye Kısayolları</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="padding:6px 0;color:#64748b;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">/</kbd></td><td>Global arama (Ctrl+K alternatifi)</td></tr>
    <tr><td style="padding:6px 0;color:#64748b;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">?</kbd></td><td>Bu yardım penceresi</td></tr>
    <tr><td style="padding:6px 0;color:#64748b;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">Esc</kbd></td><td>Modal/drawer kapat</td></tr>
    <tr><td colspan="2" style="padding:10px 0 4px;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.04em;">Tab navigasyon (g + harf)</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g b</kbd></td><td>Blacklist</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g w</kbd></td><td>Whitelist</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g p</kbd></td><td>Pending</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g l</kbd></td><td>Listeler</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g u</kbd></td><td>USOM Feed</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g k</kbd></td><td>Kaynaklar (catalog)</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g d</kbd></td><td>Dashboard</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g v</kbd></td><td>Zafiyet İzleme (CVE)</td></tr>
    <tr><td style="padding:4px 0;"><kbd style="background:#f1f5f9;padding:2px 7px;border-radius:4px;border:1px solid #cbd5e1;font-family:'Fira Code',monospace;font-size:11px;">g s</kbd></td><td>Durum &amp; Loglar</td></tr>
  </table>
  <button onclick="document.getElementById('kb-help-bg').style.display='none';document.getElementById('kb-help').style.display='none';" style="margin-top:16px;background:#16a085;color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-weight:600;">Kapat</button>
</div>
<script>
(function(){
  let gPending = false; let gTimer = null;
  const TAB_MAP = {b:'blacklist', w:'whitelist', p:'pending', l:'lists', u:'usom', k:'catalog', d:'dashboard', v:'cve', s:'status'};
  function inEditable(t){ return t && (t.tagName==='INPUT'||t.tagName==='TEXTAREA'||t.tagName==='SELECT'||t.isContentEditable); }
  function closeAll(){
    ['kb-help-bg','kb-help','ioc-drawer','ioc-drawer-bg','cve-drawer','cve-drawer-backdrop','sidebar-backdrop'].forEach(id => {
      const el = document.getElementById(id); if (el) { el.style.display='none'; el.classList?.remove('open'); }
    });
    document.getElementById('sidebar')?.classList.remove('open');
  }
  document.addEventListener('keydown', function(e){
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (inEditable(e.target)) {
      if (e.key === 'Escape') { e.target.blur(); }
      return;
    }
    if (e.key === 'Escape') { closeAll(); gPending=false; return; }
    if (e.key === '?') { e.preventDefault();
      document.getElementById('kb-help-bg').style.display='block';
      document.getElementById('kb-help').style.display='block'; return; }
    if (e.key === '/') { e.preventDefault();
      const s = document.getElementById('global-search'); if (s) { s.focus(); s.select?.(); } return; }
    if (gPending && TAB_MAP[e.key]) {
      e.preventDefault();
      const btn = document.querySelector('.tab-btn[data-tab="'+TAB_MAP[e.key]+'"]');
      btn?.click(); gPending=false; clearTimeout(gTimer); return;
    }
    if (e.key === 'g') { gPending = true; clearTimeout(gTimer);
      gTimer = setTimeout(() => gPending=false, 1200); return; }
    gPending = false;
  });
})();
</script>

<!-- R46 (T5.1): IoC Investigation Drawer (global) -->
<div id="ioc-drawer-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:200;" onclick="closeIocHistory()"></div>
<div id="ioc-drawer" style="display:none;position:fixed;top:0;right:0;width:min(720px,95vw);height:100vh;background:#fff;box-shadow:-4px 0 30px rgba(0,0,0,0.2);z-index:201;overflow-y:auto;padding:24px;">
  <button type="button" onclick="closeIocHistory()" style="position:absolute;top:12px;right:12px;background:none;border:none;font-size:22px;cursor:pointer;color:#64748b;">×</button>
  <div id="ioc-drawer-content">Yükleniyor…</div>
</div>
<!-- SPRINT6-A2 START: CVE→IoC pivot modal -->
<div id="iocPivotModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;align-items:center;justify-content:center;">
  <div style="background:#0f172a;color:#e2e8f0;border-radius:12px;width:90%;max-width:900px;max-height:85vh;display:flex;flex-direction:column;border:1px solid #1e293b;">
    <header style="display:flex;justify-content:space-between;align-items:center;padding:16px;border-bottom:1px solid #1e293b;">
      <h3 style="margin:0;color:#16a085;">&#127919; CVE &#8594; IoC Pivot · <span id="pivotCve" style="font-family:'Fira Code',monospace;color:#fff;"></span></h3>
      <button onclick="iocPivotClose()" style="background:none;color:#94a3b8;border:none;font-size:24px;cursor:pointer;">&#215;</button>
    </header>
    <div id="pivotSources" style="padding:12px 16px;border-bottom:1px solid #1e293b;font-size:12px;color:#94a3b8;">Sorgu yapılıyor…</div>
    <div style="overflow-y:auto;padding:12px 16px;flex:1;">
      <table style="width:100%;border-collapse:collapse;">
        <thead><tr style="background:#1e293b;">
          <th style="padding:8px;text-align:left;"><input type="checkbox" id="pivotAll" onchange="pivotToggleAll(this)" /></th>
          <th style="padding:8px;text-align:left;">IP / IoC</th>
          <th style="padding:8px;text-align:left;">Type</th>
          <th style="padding:8px;text-align:left;">Source</th>
          <th style="padding:8px;text-align:left;">Note</th>
        </tr></thead>
        <tbody id="pivotRows"></tbody>
      </table>
    </div>
    <footer style="padding:16px;border-top:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;gap:12px;">
      <div style="display:flex;gap:12px;align-items:center;font-size:12px;color:#94a3b8;">
        <label>TTL <input id="pivotTtl" type="number" min="1" max="365" value="14" style="width:60px;padding:4px;background:#020617;color:#e2e8f0;border:1px solid #334155;border-radius:4px;" /> gün</label>
        <label>Conf <input id="pivotConf" type="number" min="0" max="100" value="70" style="width:60px;padding:4px;background:#020617;color:#e2e8f0;border:1px solid #334155;border-radius:4px;" /></label>
        <label>TLP
          <select id="pivotTlp" style="padding:4px;background:#020617;color:#e2e8f0;border:1px solid #334155;border-radius:4px;">
            <option value="WHITE">WHITE</option><option value="GREEN">GREEN</option>
            <option value="AMBER" selected>AMBER</option><option value="RED">RED</option>
          </select>
        </label>
      </div>
      <div>
        <button onclick="iocPivotClose()" style="padding:8px 16px;background:#334155;color:#e2e8f0;border:none;border-radius:6px;cursor:pointer;margin-right:8px;">&#304;ptal</button>
        <button onclick="iocPivotAdd()" style="padding:8px 16px;background:linear-gradient(135deg,#16a085,#0e6655);color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Se&#231;ilenleri Ekle</button>
      </div>
    </footer>
  </div>
</div>
<script>
let _pivotCurrentCve = null;
async function iocPivotOpen(cve) {
  _pivotCurrentCve = cve;
  document.getElementById('pivotCve').textContent = cve;
  document.getElementById('pivotRows').innerHTML = '<tr><td colspan="5" style="padding:24px;text-align:center;color:#94a3b8;">Yükleniyor…</td></tr>';
  document.getElementById('pivotSources').textContent = 'Sorgu yapılıyor…';
  document.getElementById('iocPivotModal').style.display = 'flex';
  try {
    const r = await fetch('ioc_pivot.php?action=lookup&cve=' + encodeURIComponent(cve));
    const j = await r.json();
    document.getElementById('pivotSources').innerHTML =
      `GreyNoise: <strong style="color:#22c55e;">${j.sources?.greynoise?.count||0}</strong> (${j.sources?.greynoise?.status}) ·
       ThreatFox: <strong style="color:#22c55e;">${j.sources?.threatfox?.count||0}</strong> (${j.sources?.threatfox?.status}) ·
       Shodan match: <strong style="color:#3b82f6;">${j.sources?.shodan?.count||0}</strong>`;
    const tbody = document.getElementById('pivotRows');
    if (!j.candidates || j.candidates.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="padding:24px;text-align:center;color:#94a3b8;">Aday IoC bulunamadı</td></tr>';
      return;
    }
    tbody.innerHTML = j.candidates.map(c => {
      const blocked = c.warninglist_block;
      return `<tr style="border-bottom:1px solid #1e293b;${blocked?'opacity:0.5;':''}">
        <td style="padding:8px;"><input type="checkbox" class="pivotChk" value="${c.value}" ${blocked?'disabled':''}/></td>
        <td style="padding:8px;font-family:'Fira Code',monospace;color:#fff;">${c.value}</td>
        <td style="padding:8px;color:#cbd5e1;">${c.type}</td>
        <td style="padding:8px;"><span style="background:#1e293b;padding:2px 8px;border-radius:4px;font-size:11px;">${c.source}</span></td>
        <td style="padding:8px;color:${blocked?'#ef4444':'#94a3b8'};font-size:11px;">${blocked?'⚠ warninglist':''} ${c.malware||''}</td>
      </tr>`;
    }).join('');
  } catch(e) {
    document.getElementById('pivotRows').innerHTML = '<tr><td colspan="5" style="padding:24px;text-align:center;color:#ef4444;">Hata: ' + e.message + '</td></tr>';
  }
}
function iocPivotClose() { document.getElementById('iocPivotModal').style.display = 'none'; _pivotCurrentCve = null; }
function pivotToggleAll(cb) {
  document.querySelectorAll('.pivotChk:not(:disabled)').forEach(c => c.checked = cb.checked);
}
async function iocPivotAdd() {
  if (!_pivotCurrentCve) return;
  const ips = Array.from(document.querySelectorAll('.pivotChk:checked')).map(c => c.value);
  if (ips.length === 0) { alert('IoC seç'); return; }
  const fd = new FormData();
  fd.append('cve', _pivotCurrentCve);
  fd.append('ttl_days', document.getElementById('pivotTtl').value);
  fd.append('confidence', document.getElementById('pivotConf').value);
  fd.append('tlp', document.getElementById('pivotTlp').value);
  ips.forEach(ip => fd.append('ips[]', ip));
  const r = await fetch('ioc_pivot.php?action=add', {method:'POST', body:fd});
  const j = await r.json();
  if (j.ok) {
    alert(`Eklendi: ${j.added} · Atlandı: ${j.skipped} · Warninglist bloklu: ${j.blocked}`);
    iocPivotClose();
    if (typeof arRefresh === 'function') arRefresh();
  } else alert('Hata: ' + (j.error||'unknown'));
}
</script>
<!-- SPRINT6-A2 END -->
<!-- SPRINT6-A3 START: IoC provenance modal -->
<div id="iocProvModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9998;align-items:center;justify-content:center;">
  <div style="background:#0f172a;color:#e2e8f0;border-radius:12px;width:90%;max-width:520px;border:1px solid #1e293b;">
    <header style="display:flex;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #1e293b;">
      <h3 style="margin:0;color:#16a085;">ⓘ IoC Provenance</h3>
      <button onclick="document.getElementById('iocProvModal').style.display='none'" style="background:none;color:#94a3b8;border:none;font-size:22px;cursor:pointer;">×</button>
    </header>
    <div id="iocProvBody" style="padding:16px;"></div>
  </div>
</div>
<script>
async function iocProvShow(ip) {
  document.getElementById('iocProvBody').innerHTML = '<div style="color:#94a3b8;">Yükleniyor…</div>';
  document.getElementById('iocProvModal').style.display = 'flex';
  try {
    const r = await fetch('ioc_provenance.php?ip=' + encodeURIComponent(ip));
    const j = await r.json();
    const m = j.meta;
    if (!m) {
      document.getElementById('iocProvBody').innerHTML =
        `<div style="font-family:'Fira Code',monospace;color:#fff;font-size:14px;margin-bottom:8px;">${ip}</div>
         <div style="color:#94a3b8;font-size:13px;">Bu IP için provenance kaydı yok (manuel ekleme veya legacy entry).</div>`;
      return;
    }
    const expBadge = m.expired
      ? '<span style="background:#dc2626;color:white;padding:2px 8px;border-radius:4px;font-size:11px;">EXPIRED</span>'
      : m.expires_in_days !== undefined
        ? `<span style="background:#0e7490;color:white;padding:2px 8px;border-radius:4px;font-size:11px;">${m.expires_in_days}g kalan</span>`
        : '';
    document.getElementById('iocProvBody').innerHTML = `
      <div style="font-family:'Fira Code',monospace;color:#fff;font-size:14px;margin-bottom:12px;">${ip} ${expBadge}</div>
      <table style="width:100%;font-size:13px;">
        <tr><td style="color:#94a3b8;padding:4px 0;width:40%;">Source</td><td><strong style="color:#22c55e;">${m.source||'-'}</strong></td></tr>
        <tr><td style="color:#94a3b8;padding:4px 0;">CVE Ref</td><td><code style="color:#f59e0b;">${m.cve_ref||'-'}</code></td></tr>
        <tr><td style="color:#94a3b8;padding:4px 0;">First seen</td><td>${m.first_seen||'-'}</td></tr>
        <tr><td style="color:#94a3b8;padding:4px 0;">Sighting count</td><td>${m.sighting_count||0}</td></tr>
        <tr><td style="color:#94a3b8;padding:4px 0;">Confidence</td><td>${m.confidence||0}/100</td></tr>
        <tr><td style="color:#94a3b8;padding:4px 0;">Expires at</td><td>${m.expires_at||'-'}</td></tr>
        <tr><td style="color:#94a3b8;padding:4px 0;">Added by</td><td>${m.added_by||'-'}</td></tr>
      </table>`;
  } catch(e) {
    document.getElementById('iocProvBody').innerHTML = '<div style="color:#ef4444;">Hata: ' + e.message + '</div>';
  }
}
document.addEventListener('click', function(e) {
  const btn = e.target.closest('.ioc-prov-btn');
  if (btn && btn.dataset.ip) { iocProvShow(btn.dataset.ip); e.preventDefault(); }
});
</script>
<!-- SPRINT6-A3 END -->
<!-- R88d: SPRINT7-T7 hash routing handler kaldırıldı.
     Tab navigation artık ?tab= query string-only (Linear/GitHub/Notion stili).
     hashchange listener + parseTabFromHash + applyTabFromHash SİLİNDİ. -->
<!-- R88e: vanilla fetch sidebar swap (htmx replaced — 4-agent debate winner) -->
<script>
(function() {
  var TARGET_ID = 'bl-content';
  var content = document.getElementById(TARGET_ID);
  var loading = document.getElementById('bl-loading');
  if (!content) return;

  function buildFragmentUrl(href) {
    try {
      var u = new URL(href, window.location.href);
      u.searchParams.set('fragment', 'blacklist-grid');
      return u.pathname + u.search;
    } catch(e) {
      return href + (href.indexOf('?') >= 0 ? '&' : '?') + 'fragment=blacklist-grid';
    }
  }

  function swapContent(href, pushUrl) {
    if (loading) loading.classList.add('visible');
    content.style.opacity = '0.5';
    console.log('[R88e] swap', href);

    fetch(buildFragmentUrl(href), { credentials: 'same-origin', headers: { 'X-Fragment': '1' } })
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.text();
      })
      .then(function(html) {
        content.innerHTML = html;
        // R91d: pushUrl normalize — list var page yoksa page=1 explicit
        if (pushUrl) {
          try {
            var _u = new URL(pushUrl, window.location.href);
            if (_u.searchParams.has('list') && !_u.searchParams.has('page')) {
              _u.searchParams.set('page', '1');
              pushUrl = _u.pathname + _u.search;
            }
          } catch(e) {}
          history.pushState({}, '', pushUrl);
        }

        // Active state sync (R90: .bl-listnav v2 + .listnav legacy)
        var newUrl = new URL(window.location.href);
        var activeSlug = newUrl.searchParams.get('list') || 'all';
        document.querySelectorAll('.bl-listnav li, .listnav li').forEach(function(li){
          var a = li.querySelector('a[data-bl-list]');
          var slug = a ? (a.dataset.blList || '') : (li.dataset.slug || '');
          li.classList.toggle('active', slug === activeSlug);
        });

        // Drawer reset
        document.body.classList.remove('drawer-open');
        var d = document.querySelector('.bl-drawer');
        var b = document.querySelector('.bl-drawer-backdrop');
        if (d) { d.classList.remove('open'); d.hidden = true; }
        if (b) { b.classList.remove('open'); b.hidden = true; }

        // Scroll position reset
        content.scrollTop = 0;
      })
      .catch(function(err) {
        console.warn('[R88e] fetch fail, full reload fallback:', err);
        window.location.href = pushUrl || href;
      })
      .finally(function() {
        if (loading) loading.classList.remove('visible');
        content.style.opacity = '';
      });
  }

  // Sidebar click intercept (event delegation)
  // R89e: pagination link'leri (data-bl-page) de swap'a dahil — snappy + URL state korunur
  // R90: .bl-listnav (v2 cerrahi port) selektörü eklendi
  document.addEventListener('click', function(e) {
    var a = e.target.closest('.bl-listnav a[data-bl-list], .listnav a[data-bl-list], .listnav a[href*="?list="], .listnav a[href*="?tab=blacklist"], #tab-blacklist .pagination a[data-bl-page]');
    if (!a) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return; // new-tab izin
    e.preventDefault();
    var href = a.getAttribute('href');
    swapContent(href, href);
  });

  // Browser back/forward
  window.addEventListener('popstate', function(e) {
    // Basit fallback: full reload (cache snapshot complexity'i kabul edilmiyor)
    window.location.reload();
  });
})();
</script>
<!-- SPRINT7-I1 SIDEBAR-ACTIONS START -->
<script>
(function() {
  // Delegated click on .listnav for ln-* action buttons
  document.addEventListener('click', async function(e) {
    var btn = e.target.closest('.listnav .ln-edit, .listnav .ln-del, .listnav .ln-fetch, .listnav .ln-toggle');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();

    var li = btn.closest('li');
    var slug = li && li.dataset.slug;
    var kind = li && li.dataset.kind;
    if (!slug) return;

    // ln-edit (manual) — show prompt for new name
    if (btn.classList.contains('ln-edit')) {
      var current = li.querySelector('a').textContent.trim();
      var newName = prompt('Liste adı:', current);
      if (!newName || newName.trim() === '' || newName === current) return;
      try {
        var fd = new FormData();
        fd.append('action', 'rename');
        fd.append('slug', slug);
        fd.append('new_name', newName.trim());
        var r = await fetch('lists.php', { method: 'POST', body: fd });
        var j = await r.json().catch(function() { return { ok: false, error: 'Sunucu yanıtı işlenemedi' }; });
        if (j.ok) { location.reload(); } else { alert('Hata: ' + (j.error || 'bilinmiyor')); }
      } catch (err) { alert('Ağ hatası: ' + err.message); }
      return;
    }

    // ln-del (manual) — confirm + delete
    if (btn.classList.contains('ln-del')) {
      if (!confirm('"' + (li.querySelector('a').textContent.trim()) + '" listesini sil?\n\nNot: Liste boş değilse silinmez.')) return;
      try {
        var fd = new FormData();
        fd.append('action', 'delete');
        fd.append('slug', slug);
        var r = await fetch('lists.php', { method: 'POST', body: fd });
        var j = await r.json().catch(function() { return { ok: false, error: 'Sunucu yanıtı işlenemedi' }; });
        if (j.ok) { location.reload(); } else { alert('Hata: ' + (j.error || 'bilinmiyor')); }
      } catch (err) { alert('Ağ hatası: ' + err.message); }
      return;
    }

    // ln-fetch (external) — trigger source manager update_source
    if (btn.classList.contains('ln-fetch')) {
      try {
        var fd = new FormData();
        fd.append('action', 'fetch_now');
        fd.append('slug', slug);
        var r = await fetch('lists.php', { method: 'POST', body: fd });
        var j = await r.json().catch(function() { return { ok: false, error: 'Sunucu yanıtı işlenemedi' }; });
        if (j.ok) {
          alert('Çekildi: ' + (j.count || 0) + ' kayıt');
          location.reload();
        } else { alert('Hata: ' + (j.error || 'bilinmiyor')); }
      } catch (err) { alert('Ağ hatası: ' + err.message); }
      return;
    }

    // ln-toggle (external) — enabled flip
    if (btn.classList.contains('ln-toggle')) {
      if (!confirm('Bu kaynağı devre dışı bırak/etkinleştir?')) return;
      try {
        var fd = new FormData();
        fd.append('action', 'toggle');
        fd.append('slug', slug);
        var r = await fetch('lists.php', { method: 'POST', body: fd });
        var j = await r.json().catch(function() { return { ok: false, error: 'Sunucu yanıtı işlenemedi' }; });
        if (j.ok) { location.reload(); } else { alert('Hata: ' + (j.error || 'bilinmiyor')); }
      } catch (err) { alert('Ağ hatası: ' + err.message); }
      return;
    }
  });
})();
</script>
<!-- SPRINT7-I1 SIDEBAR-ACTIONS END -->

<!-- R84 (UX Pass-2 §2): Expandable row click toggle -->
<script>
(function () {
  var table = document.getElementById('bl-data-table');
  if (!table) return;
  table.addEventListener('click', function (e) {
    var row = e.target.closest('tr.bl-row');
    if (!row) return;
    // Guard: ignore clicks originating from interactive cells/elements
    if (e.target.closest('a, button, input, select, textarea, label, .bl-actions')) return;
    var id = row.getAttribute('data-id');
    if (!id) return;
    var detail = table.querySelector('tr.bl-row-detail[data-for="' + (window.CSS && CSS.escape ? CSS.escape(id) : id.replace(/"/g, '\\"')) + '"]');
    if (!detail) return;
    var nowHidden = detail.classList.toggle('hidden');
    row.classList.toggle('expanded', !nowHidden);
  });
})();
</script>
</body>
</html>

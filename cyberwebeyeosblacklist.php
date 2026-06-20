<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
header('Content-Type: text/html; charset=utf-8');

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
$instance_name = isset($settings['instance_name']) ? $settings['instance_name'] . ' - Sadece Görüntüleme' : 'Cyberwebeyeos Blacklist - Sadece Görüntüleme';

// READ-ONLY MODE: Bu sayfa sadece görüntüleme içindir
$readonly_mode = true;

// Dosya yolları
$file_path = "/var/www/html/blacklist.txt";               // Manuel güncelleme için

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
    list($ip, $mask) = explode('/', $cidr);
    $ip_long = ip2long($ip);
    $mask = (int)$mask;
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
            // Yorum satırlarını atla
            $line = trim($line);
            if (!empty($line) && substr($line, 0, 1) !== '#') {
                // IP formatını kontrol et (basit bir kontrol)
                if (filter_var(explode('/', $line)[0], FILTER_VALIDATE_IP) || 
                    (strpos($line, '/') !== false && validate_cidr($line))) {
                    $cyberwebeyeos_blocks[] = $line;
                }
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
function display_blacklist($search_ip = '', $per_page = 10, $page = 1, $list_filter = 'all', $readonly_mode = false) {
    global $file_path;

    // Manuel güncellenebilen liste - sadece gerektiğinde oku
    $manual_items = [];
    if ($list_filter === 'all' || $list_filter === 'Manuel') {
        $manual_items = file_exists($file_path) ? file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
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
    
    // Arama yapılıyorsa filtrele
if ($search_ip) {
    $filtered_items = [];
    $search_ip_only = $search_ip;
    
    // Eğer arama terimi CIDR formatındaysa, sadece IP kısmını çıkar
    if (strpos($search_ip, '/') !== false) {
        $search_ip_only = explode('/', $search_ip)[0];
    }
    
    foreach ($combined_items as $item) {
        // Verinin herhangi bir kısmında doğrudan metin eşleşmesi (mevcut işlevsellik)
        if (strpos($item['data'], $search_ip) !== false) {
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
    
    $total_items = count($filtered_items);
    $total_pages = ceil($total_items / $per_page);
    if ($total_pages < 1) $total_pages = 1;
    $page = max(1, min($page, $total_pages));
    $start_index = ($page - 1) * $per_page;
    $displayed_items = array_slice($filtered_items, $start_index, $per_page);
    // Liste filtre seçenekleri
    echo "<div class='search-bar'>";
    echo "<form method='get' action='" . htmlspecialchars($_SERVER["PHP_SELF"]) . "'>";
    echo "<table class='search-table' cellpadding='0' cellspacing='0'><tr>";
    echo "<td style='width:100%'><input type='text' name='search' class='form-control' placeholder='IP Adresi veya FQDN ara...' value='" . htmlspecialchars($search_ip) . "'></td>";
    echo "<td><button type='submit' class='btn btn-primary'><i class='fas fa-search'></i> Ara</button></td>";
    echo "</tr></table>";
    echo "<input type='hidden' name='per_page' value='" . $per_page . "'>";
    echo "<input type='hidden' name='list_filter' value='" . $list_filter . "'>";
    echo "</form>";
    echo "</div>";
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
    
    echo "<div class='table-responsive'>";
    if (!$readonly_mode) {
        echo "<form method='post' action='delete.php'>";
    }
    echo "<table class='data-table'>";
    echo "<thead>";
    echo "<tr>";
    if (!$readonly_mode) {
        echo "<th><input type='checkbox' id='select-all' onclick='toggleAllCheckboxes()'></th>";
    }
    echo "<th>IP Adresi</th>
            <th>Yorum</th>
            <th>FQDN</th>
            <th>Jira Numarası/URL</th>
            <th>Tarih/Saat</th>
            <th>Liste</th>";
    if (!$readonly_mode) {
        echo "<th>İşlem</th>";
    }
    echo "</tr>";
    echo "</thead>";
    echo "<tbody>";
    
    if (count($displayed_items) == 0) {
        $colspan = $readonly_mode ? '6' : '8';
        echo "<tr><td colspan='$colspan' class='no-records'>Kayıt bulunamadı</td></tr>";
    } else {
        foreach ($displayed_items as $item) {
            if (!empty($item['data'])) {
                // Manuel liste için normal ayrıştırma
                $entry_parts = explode("|", $item['data']);
                if (count($entry_parts) < 5) {
                    // Bu satırı atla veya boş değerlerle doldur
                    $entry_parts = array_pad($entry_parts, 5, '');
                }
                list($ip, $comment, $date, $fqdn, $jira) = $entry_parts;
                
                echo "<tr>";
                if (!$readonly_mode) {
                    if ($item['editable']) {
                        echo "<td><input type='checkbox' name='selected_ips[]' value='$ip' class='record-checkbox'></td>";
                    } else {
                        echo "<td class='center'>-</td>";
                    }
                }
                echo "<td>" . htmlspecialchars($ip) . "</td>
                      <td>" . htmlspecialchars($comment) . "</td>
                      <td>" . htmlspecialchars($fqdn) . "</td>
                      <td>" . htmlspecialchars($jira) . "</td>
                      <td>" . htmlspecialchars($date) . "</td>
                      <td>" . htmlspecialchars($item['source']) . "</td>";
                if (!$readonly_mode) {
                    if ($item['editable']) {
                        echo "<td><a href='edit.php?ip=$ip' class='btn btn-edit'>Düzenle</a></td>";
                    } else {
                        echo "<td class='center'>Okunabilir</td>";
                    }
                }
                echo "</tr>";
            }
        }
    }
    
    echo "</tbody>";
    echo "</table>";

    if (!$readonly_mode) {
        echo "<div class='table-actions'>";
        echo "<input type='submit' name='delete' value='Seçilenleri Sil' class='btn btn-delete'>";
        echo "</div>";
        echo "</form>";
    }
    echo "</div>"; // table-responsive end
    
            echo "<div class='record-info'>Toplam: <b>$total_items</b> kayıt</div>";
    
    // Sayfalama
    if ($total_pages > 1) {
        echo "<div class='pagination'>";
        if ($page > 1) {
            echo "<a href='?page=" . ($page - 1) . "&per_page=$per_page&search=$search_ip&list_filter=$list_filter' class='page-link'>&laquo; Önceki</a>";
        }
        
        // Sayfa numaralarını göster
        $max_pages_to_show = 5;
        $start_page = max(1, min($page - floor($max_pages_to_show / 2), $total_pages - $max_pages_to_show + 1));
        $end_page = min($start_page + $max_pages_to_show - 1, $total_pages);
        
        if ($start_page > 1) {
            echo "<a href='?page=1&per_page=$per_page&search=$search_ip&list_filter=$list_filter' class='page-link'>1</a>";
            if ($start_page > 2) {
                echo "<span class='page-ellipsis'>...</span>";
            }
        }
        
        for ($i = $start_page; $i <= $end_page; $i++) {
            if ($i == $page) {
                echo "<span class='page-link current'>$i</span>";
            } else {
                echo "<a href='?page=$i&per_page=$per_page&search=$search_ip&list_filter=$list_filter' class='page-link'>$i</a>";
            }
        }
        
        if ($end_page < $total_pages) {
            if ($end_page < $total_pages - 1) {
                echo "<span class='page-ellipsis'>...</span>";
            }
            echo "<a href='?page=$total_pages&per_page=$per_page&search=$search_ip&list_filter=$list_filter' class='page-link'>$total_pages</a>";
        }
        
        if ($page < $total_pages) {
            echo "<a href='?page=" . ($page + 1) . "&per_page=$per_page&search=$search_ip&list_filter=$list_filter' class='page-link'>Sonraki &raquo;</a>";
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
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['sync_blacklist']) && !$readonly_mode) {
    if (sync_manual_blacklist_to_cyberwebeyeos()) {
        $_SESSION['message'] = "Manuel liste başarıyla senkronize edildi.";
    } else {
        $_SESSION['message'] = "Manuel listede değişiklik yapılmadı, zaten güncel.";
    }
}

// Manuel ekleme (POST ile)
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['ip_address']) && !$readonly_mode) {
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
            $ip_addresses = explode(',', $ip_input);
            foreach ($ip_addresses as $ip_input) {
                $ip_input = trim($ip_input);
                if (strpos($ip_input, '/') === false) {
                    $ip_input .= '/32';
                }
                if (is_private_ip(explode('/', $ip_input)[0])) {
                    $_SESSION['message'] .= "Özel IP adresi (Private IP) eklenemez: $ip_input<br>";
                    continue;
                }
                if (!validate_ip($ip_input)) {
                    $_SESSION['message'] .= "Geçersiz IP adresi veya subnet prefix: $ip_input<br>";
                    continue;
                }
                if (is_cyberwebeyeos_ip($ip_input)) {
                    $_SESSION['message'] .= "Bu IP, cyberwebeyeos ve cyberwebeyeos ortamlarına aittir ve eklenemez: $ip_input<br>";
                    continue;
                }
                $existing_ip_or_subnet = ip_exists($ip_input);
                if ($existing_ip_or_subnet) {
                    $_SESSION['message'] .= "Bu IP adresi veya subnet zaten mevcut: $ip_input, mevcut subnet: $existing_ip_or_subnet<br>";
                    continue;
                } else {
                    list($ip, $cidr) = explode('/', $ip_input);
                    if (is_private_ip($ip)) {
                        $_SESSION['message'] .= "Özel IP adresi (Private IP) eklenemez: $ip_input<br>";
                        continue;
                    } elseif (!validate_ip($ip_input)) {
                        $_SESSION['message'] .= "Geçersiz IP adresi veya subnet prefix: $ip_input<br>";
                        continue;
                    } else {
                        $file_content = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                        $skip = false;
                        foreach ($file_content as $item) {
                            list($existing_ip) = explode("|", $item);
                            if (strpos($existing_ip, '/') !== false) {
                                if (is_ip_in_subnet_range($ip, $existing_ip)) {
                                    $_SESSION['message'] .= "Bu IP, mevcut subnet aralığındadır ve eklenemez: $ip_input<br>";
                                    $skip = true;
                                    break;
                                }
                            }
                        }
                        if ($skip) {
                            continue;
                        }
                        $date = new DateTime('now', new DateTimeZone('Europe/Istanbul'));
                        $date_string = $date->format('Y-m-d H:i:s');
                        $new_entry = "$ip_input|$comment|$date_string|$fqdn|$jira\n";
                        file_put_contents($file_path, $new_entry, FILE_APPEND);
                        $_SESSION['message'] .= "IP adresi başarıyla eklendi: $ip_input<br>";
                        write_to_cyberwebeyeos_blacklist($ip_input, $fqdn);
                    }
                }
            }
        }
    }
}

// Excel ile toplu ekleme işlemi
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['excel_file']) && !$readonly_mode) {
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
                $error_messages[] = "Özel IP adresi (Private IP) eklenemez: $ip";
                continue; // Özel IP'yi atla
            }
            // cyberwebeyeos IP bloklarına ait mi kontrol et
                        if (is_cyberwebeyeos_ip($ip)) {
                $error_messages[] = "Bu IP, cyberwebeyeos ortamına aittir ve eklenemez: $ip";
                continue;
            }
            // IP geçerlilik kontrolü
                        if (!validate_ip($ip)) {
                $error_messages[] = "Geçersiz IP adresi veya subnet prefix: $ip";
                continue; // Geçersizse bir sonraki satıra geç
            } elseif (ip_exists($ip) || subnet_exists($ip)) {
                $error_messages[] = "Bu IP adresi veya subnet zaten mevcut: $ip";
                continue; // Zaten mevcutsa bir sonraki satıra geç
            }
        }

        // FQDN doğrulama
                if (!empty($fqdn)) {
            if (!validate_fqdn($fqdn)) {
                $error_messages[] = "Geçersiz FQDN: $fqdn";
                continue; // Geçersizse bir sonraki satıra geç
            } elseif (fqdn_exists($fqdn)) {
                $error_messages[] = "Bu FQDN zaten mevcut: $fqdn";
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
                        write_to_cyberwebeyeos_blacklist($ip, $fqdn);
        } elseif (!empty($fqdn)) {
            // FQDN eklerken IP yoksa "N/A" kullan
                        $new_entry = "N/A|$comment|$date_string|$fqdn|$jira\n";
            file_put_contents($file_path, $new_entry, FILE_APPEND);
            write_to_cyberwebeyeos_blacklist('N/A', $fqdn);
        }
        $successful_entries[] = !empty($ip) ? $ip : $fqdn; // Başarıyla eklenen girişleri diziye ekle
    }

    // Bildirim oluştur
        $messages = [];
    if (!empty($successful_entries)) {
        $messages[] = "Başarıyla eklendi: " . implode(', ', $successful_entries);
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
$list_filter = isset($_GET['list_filter']) ? trim($_GET['list_filter']) : 'all';
$per_page_options = [10, 25, 50, 100];
?>



<!DOCTYPE html>
<html lang="tr">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($instance_name); ?> - Yönetim Arayüzü</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="/monitoring_check_modal.js"></script>
    <style>
        :root {
            --primary-color: #005588;
            --primary-light: #2579b0;
            --secondary-color: #333333;
            --success-color: #28a745;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #17a2b8;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
            --border-color: #dee2e6;
            --shadow-color: rgba(0, 0, 0, 0.1);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        /* Header Styles */
        .header {
            background: linear-gradient(135deg, var(--primary-color), #003c6c);
            color: white;
            padding: 1rem;
            box-shadow: 0 2px 5px var(--shadow-color);
            position: relative;
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1400px;
            margin: 0 auto;
        }

        .header-title {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .header-actions {
            display: flex;
            gap: 1rem;
        }

        .logo {
            height: 40px;
        }

        /* Main Layout */
        .container {
            max-width: 1600px;
            margin: 20px auto;
            padding: 0 15px;
            display: flex;
            gap: 20px;
        }

        .main-content {
            flex: 4;
            min-width: 0;
        }

        .sidebar {
            flex: 1;
            min-width: 280px;
            max-width: 350px;
        }

        /* Card Styles */
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px var(--shadow-color);
            margin-bottom: 25px;
            overflow: hidden;
        }

        .card-header {
            padding: 18px 25px;
            background-color: #f8f9fa;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--secondary-color);
            margin: 0;
        }

        .card-body {
            padding: 20px;
        }

        /* Form Styles */
        .form-group {
            margin-bottom: 15px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: var(--secondary-color);
        }

        .form-control {
            width: 100%;
            padding: 8px 12px;
            font-size: 14px;
            line-height: 1.5;
            color: #495057;
            background-color: #fff;
            border: 1px solid #ced4da;
            border-radius: 4px;
            transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
        }

        .form-control:focus {
            border-color: var(--primary-light);
            outline: 0;
            box-shadow: 0 0 0 0.2rem rgba(0, 85, 136, 0.25);
        }

        /* Button Styles */
        .btn {
            display: inline-block;
            font-weight: 500;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            user-select: none;
            border: 1px solid transparent;
            padding: 8px 16px;
            font-size: 14px;
            line-height: 1.5;
            border-radius: 4px;
            transition: color 0.15s ease-in-out, background-color 0.15s ease-in-out, border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
            cursor: pointer;
            text-decoration: none;
        }

        .btn-primary {
            color: #fff;
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .btn-primary:hover {
            background-color: var(--primary-light);
            border-color: var(--primary-light);
        }

        .btn-success {
            color: #fff;
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .btn-success:hover {
            background-color: #218838;
            border-color: #1e7e34;
        }

        .btn-danger {
            color: #fff;
            background-color: var(--danger-color);
            border-color: var(--danger-color);
        }

        .btn-danger:hover {
            background-color: #c82333;
            border-color: #bd2130;
        }

        .btn-warning {
            color: #212529;
            background-color: var(--warning-color);
            border-color: var(--warning-color);
        }

        .btn-warning:hover {
            background-color: #e0a800;
            border-color: #d39e00;
        }

        .btn-info {
            color: #fff;
            background-color: var(--info-color);
            border-color: var(--info-color);
        }

        .btn-info:hover {
            background-color: #138496;
            border-color: #117a8b;
        }

        .btn-edit {
            color: #fff;
            background-color: var(--info-color);
            border-color: var(--info-color);
        }

        .btn-edit:hover {
            background-color: #138496;
            border-color: #117a8b;
        }

        .btn-delete {
            color: #fff;
            background-color: var(--danger-color);
            border-color: var(--danger-color);
        }

        /* Table Styles */
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            margin-bottom: 15px;
            border-radius: 4px;
            max-width: 100%;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }

        .data-table th, 
        .data-table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
            vertical-align: middle;
            word-wrap: break-word;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .data-table thead th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: var(--secondary-color);
            border-bottom: 2px solid var(--border-color);
            white-space: nowrap;
            padding: 12px;
        }

        .data-table tbody tr {
            transition: background-color 0.2s ease;
        }

        .data-table tbody tr:hover {
            background-color: rgba(0, 85, 136, 0.05);
        }

        /* Sütun genişlikleri - daha kompakt */
        .data-table th:nth-child(1), .data-table td:nth-child(1) { width: 40px; text-align: center; }
        .data-table th:nth-child(2), .data-table td:nth-child(2) { width: 16%; }
        .data-table th:nth-child(3), .data-table td:nth-child(3) { width: 18%; }
        .data-table th:nth-child(4), .data-table td:nth-child(4) { width: 14%; }
        .data-table th:nth-child(5), .data-table td:nth-child(5) { width: 14%; }
        .data-table th:nth-child(6), .data-table td:nth-child(6) { width: 14%; }
        .data-table th:nth-child(7), .data-table td:nth-child(7) { width: 10%; }
        .data-table th:nth-child(8), .data-table td:nth-child(8) { width: 80px; text-align: center; }

        .data-table .center {
            text-align: center;
        }

        .no-records {
            text-align: center;
            padding: 30px;
            color: #6c757d;
            font-style: italic;
        }

        /* Table Action Bar */
        .action-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
            padding: 10px 0;
        }

        .search-section {
            display: flex;
            gap: 10px;
            flex-grow: 1;
            max-width: 600px;
        }

        .search-section .form-control {
            flex-grow: 1;
            min-width: 250px;
        }

        .filter-section, 
        .per-page-section {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .table-actions {
            margin-top: 20px;
            display: flex;
            justify-content: flex-start;
            gap: 10px;
        }

        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            padding: 20px 0;
            gap: 8px;
        }

        .page-link {
            padding: 10px 15px;
            border: 1px solid var(--border-color);
            color: var(--primary-color);
            background-color: #fff;
            text-decoration: none;
            border-radius: 4px;
            transition: all 0.2s ease;
        }

        .page-link:hover {
            background-color: #f8f9fa;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        .page-link.current {
            background-color: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
            font-weight: bold;
        }

        .page-ellipsis {
            padding: 10px 15px;
            color: #6c757d;
        }

        /* Alert Styles */
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
            position: relative;
        }

        .alert-success {
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }

        .alert-danger {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }

        .alert-warning {
            color: #856404;
            background-color: #fff3cd;
            border-color: #ffeeba;
        }

        .alert-info {
            color: #0c5460;
            background-color: #d1ecf1;
            border-color: #bee5eb;
        }

        .alert .close {
            position: absolute;
            top: 15px;
            right: 15px;
            font-size: 1.25rem;
            font-weight: 700;
            line-height: 1;
            color: inherit;
            text-shadow: 0 1px 0 #fff;
            opacity: 0.5;
            background: none;
            border: none;
            cursor: pointer;
        }

        /* Record Info */
        .record-info {
            margin: 15px 0;
            color: #6c757d;
            font-style: italic;
        }

        /* Footer */
        .footer {
            padding: 15px;
            text-align: center;
            background-color: var(--dark-color);
            color: white;
            margin-top: 30px;
            font-size: 0.9rem;
        }

        /* Responsive adjustments */
        @media (max-width: 1200px) {
            .container {
                flex-direction: column;
            }
            
            .main-content, .sidebar {
                width: 100%;
                max-width: 100%;
            }
        }
        
        @media (max-width: 992px) {            
            .header-content {
                flex-direction: column;
                text-align: center;
                gap: 10px;
            }
            
            .header-actions {
                justify-content: center;
            }
        }

        /* File Upload styles */
        .file-upload {
            position: relative;
            overflow: hidden;
            margin-top: 10px;
            display: inline-block;
        }

        .file-upload input[type=file] {
            position: absolute;
            top: 0;
            right: 0;
            min-width: 100%;
            min-height: 100%;
            font-size: 100px;
            text-align: right;
            filter: alpha(opacity=0);
            opacity: 0;
            outline: none;
            background: white;
            cursor: inherit;
            display: block;
        }

        .file-upload-label {
            display: inline-block;
            padding: 8px 16px;
            color: white;
            background-color: var(--primary-color);
            border-radius: 4px;
            cursor: pointer;
        }

        .file-name {
            margin-left: 10px;
            font-style: italic;
        }

        /* Helper Classes */
        .text-center {
            text-align: center;
        }

        .mt-1 { margin-top: 0.25rem !important; }
        .mt-2 { margin-top: 0.5rem !important; }
        .mt-3 { margin-top: 1rem !important; }
        .mb-1 { margin-bottom: 0.25rem !important; }
        .mb-2 { margin-bottom: 0.5rem !important; }
        .mb-3 { margin-bottom: 1rem !important; }
        
        /* Yeni eklenen ml-auto sınıfı */
        .ml-auto {
            margin-left: auto;
        }

        /* Yeni Eklenen: Status Panel Stilleri */
        .badge {
            display: inline-block;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 600;
            line-height: 1;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 4px;
        }

        .badge-success {
            color: #fff;
            background-color: #28a745;
        }

        .badge-danger {
            color: #fff;
            background-color: #dc3545;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
            line-height: 1.5;
        }

        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
        }

        .status-active {
            background-color: #28a745;
            box-shadow: 0 0 8px rgba(40, 167, 69, 0.6);
        }

        .status-inactive {
            background-color: #dc3545;
        }

        .log-entry {
            margin-bottom: 5px;
            padding: 8px;
            background-color: #ffffff;
            border-left: 3px solid #005588;
            border-radius: 3px;
            font-size: 11px;
        }

        .log-entry:hover {
            background-color: #f8f9fa;
        }

        /* Spine Access Control Modal Styles */
        .spine-modal {
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.6);
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .spine-modal-content {
            background-color: #fff;
            margin: 3% auto;
            padding: 0;
            border-radius: 12px;
            width: 90%;
            max-width: 900px;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: 0 15px 50px rgba(0,0,0,0.3);
            animation: slideDown 0.3s ease;
        }

        @keyframes slideDown {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .spine-modal-header {
            background: linear-gradient(135deg, #6f42c1, #5a2d91);
            color: white;
            padding: 20px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .spine-modal-header h2 {
            font-size: 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .spine-modal-close {
            color: white;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
            background: none;
            border: none;
        }

        .spine-modal-close:hover {
            transform: scale(1.2);
        }

        .spine-modal-body {
            padding: 25px;
            max-height: calc(90vh - 150px);
            overflow-y: auto;
        }

        .spine-info-box {
            background: #f3e8ff;
            border: 1px solid #d4b5ff;
            border-left: 4px solid #6f42c1;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }

        .spine-info-box p {
            color: #4a2c6a;
            font-size: 13px;
            line-height: 1.6;
        }

        .spine-search-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
        }

        .spine-search-form label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        .spine-search-row {
            display: flex;
            gap: 15px;
        }

        .spine-search-input {
            flex: 1;
            padding: 12px 15px;
            font-size: 15px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
        }

        .spine-search-input:focus {
            border-color: #6f42c1;
            outline: none;
            box-shadow: 0 0 0 3px rgba(111, 66, 193, 0.1);
        }

        .spine-search-btn {
            padding: 12px 25px;
            background: #6f42c1;
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s;
        }

        .spine-search-btn:hover {
            background: #5a2d91;
            transform: translateY(-2px);
        }

        .spine-search-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }

        .spine-result-box {
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            animation: slideDown 0.3s ease;
        }

        .spine-result-found {
            background: #d4edda;
            border: 2px solid #28a745;
        }

        .spine-result-not-found {
            background: #f8d7da;
            border: 2px solid #dc3545;
        }

        .spine-result-header {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 15px;
        }

        .spine-result-details {
            background: rgba(255,255,255,0.5);
            padding: 15px;
            border-radius: 6px;
        }

        .spine-result-details table {
            width: 100%;
            border-collapse: collapse;
        }

        .spine-result-details td {
            padding: 8px;
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }

        .spine-result-details td:first-child {
            font-weight: 600;
            width: 140px;
        }

        .spine-members-section h3 {
            font-size: 16px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .spine-member-count {
            background: #6f42c1;
            color: white;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 12px;
        }

        .spine-filter-input {
            width: 100%;
            padding: 10px 15px;
            margin-bottom: 15px;
            border: 2px solid #dee2e6;
            border-radius: 6px;
            font-size: 14px;
        }

        .spine-filter-input:focus {
            border-color: #6f42c1;
            outline: none;
        }

        .spine-members-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .spine-members-table th,
        .spine-members-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }

        .spine-members-table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .spine-members-table tr:hover {
            background: #f8f9fa;
        }

        .spine-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }

        .spine-badge-subnet {
            background: #e7f3ff;
            color: #004085;
        }

        .spine-badge-range {
            background: #fff3cd;
            color: #856404;
        }

        .spine-loading {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }

        .spine-loading i {
            font-size: 40px;
            animation: spin 1s linear infinite;
        }

        .spine-error-box {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }

        .spine-open-new-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 10px;
        }

        .spine-open-new-btn:hover {
            background: #138496;
        }
    </style>
</head>

<body>
    <header class="header">
        <div class="header-content">
            <h1 class="header-title"><?php echo htmlspecialchars($instance_name); ?></h1>
            <div class="header-actions">
                <a href="whitelist.php?from=readonly" class="btn btn-success">
                    <i class="fas fa-shield-alt"></i> Beyaz Liste Görüntüle
                </a>
                <?php if (!$readonly_mode): ?>
                    <?php
                    require_once __DIR__ . '/pending_ips_helper.php';
                    $pending_count = count_pending_ips();
                    $badge_style = $pending_count > 0 ? 'background-color: #dc3545; color: white; padding: 2px 6px; border-radius: 10px; font-size: 11px; margin-left: 5px;' : 'display: none;';
                    ?>
                    <a href="#pending-ips-section" class="btn btn-warning" style="position: relative;">
                        <i class="fas fa-clock"></i> Onay Bekleyen IP'ler
                        <span style="<?php echo $badge_style; ?>"><?php echo $pending_count; ?></span>
                    </a>
                    <a href="move_to_pending.php" class="btn btn-info">
                        <i class="fas fa-exchange-alt"></i> IP'yi Pending'e Taşı
                    </a>
                <?php endif; ?>
                <a href="#" class="btn btn-primary" onclick="openCyberwebeyeosBlacklist()">
                    <i class="fas fa-exchange-alt"></i> Cyberwebeyeos Blacklist Arayüzü
                </a>
            </div>
            <img src="/images/<?php echo htmlspecialchars($logo); ?>" alt="<?php echo htmlspecialchars($instance_name); ?> Logo" class="logo">
        </div>
    </header>

    <script>
        function openCyberwebeyeosBlacklist() {
            // Portal iframe içindeysek üst pencerede Cyberwebeyeos sekmesine geç
            try {
                if (window.top && window.top !== window.self && typeof window.top.switchBlacklistTab === 'function') {
                    window.top.switchBlacklistTab('cyberwebeyeos');
                    return;
                }
            } catch (e) { /* cross-origin fallback */ }

            // Doğrudan erişimde readonly Cyberwebeyeos blacklist sayfasına yönlendir
            window.location.href = "https://portal.cyberwebeyeos.com.tr/cyberwebeyeos/cyberwebeyeosblacklist.php";
        }
    </script>

    <?php if (isset($_SESSION['message']) && !empty($_SESSION['message'])): ?>
    <div class="container">
        <div class="alert alert-info">
            <?php echo $_SESSION['message']; ?>
            <button type="button" class="close" onclick="this.parentElement.style.display='none'">&times;</button>
        </div>
    </div>
    <?php unset($_SESSION['message']); endif; ?>

    <div class="container">
        <!-- Sol taraf - Kara Liste Tablosu -->
        <main class="main-content">
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-ban"></i> Kara Liste (Blacklist) 
                        <span class="list-info" id="current-list-info">
                            <!-- Görüntülenen liste bilgisi buraya gelecek -->
                            <?php echo ($list_filter === 'all' ? 'Tüm Listeler' : $list_filter); ?>
                        </span>
                    </h2>
                    
                    <!-- Senkronizasyon butonu -->
                    <?php if (!$readonly_mode): ?>
                    <form method="post" action="" class="ml-auto">
                        <button type="submit" name="sync_blacklist" class="btn btn-primary btn-sm">
                            <i class="fas fa-sync"></i> Manuel Listeyi Senkronize Et
                        </button>
                    </form>
                    <?php endif; ?>
                </div>
                <div class="card-body">
                    <?php display_blacklist($search_ip, $per_page, $page, $list_filter, $readonly_mode); ?>
                </div>
            </div>
        </main>

        <!-- Sağ taraf - Kontrol Paneli ve Formlar -->
        <aside class="sidebar">
            <!-- Kontrol Mekanizmaları (Checklist) - Readonly modda da görünür -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-check-square"></i> Kontrol Mekanizmaları</h3>
                </div>
                <div class="card-body">
                    <p style="margin-bottom: 15px; font-size: 13px; color: #6c757d;">
                        Hızlı bağlantı ve port kontrol araçları
                    </p>

                    <!-- S2S VPN Tunnel Kontrolü -->
                    <button class="btn btn-info btn-block" onclick="openVPNTunnelMonitor()" style="margin-bottom: 10px; background-color: #17a2b8; color: #fff; border-color: #17a2b8;">
                        <i class="fas fa-project-diagram"></i> S2S VPN Tunnel Kontrolü
                    </button>

                    <!-- İnternet Kontrolü -->
                    <button class="btn btn-success btn-block" onclick="checkInternet()" style="margin-bottom: 10px;">
                        <i class="fas fa-globe"></i> İnternet Kontrolü
                    </button>

                    <!-- SSL-VPN Kontrolü -->
                    <button class="btn btn-info btn-block" onclick="checkSSLVPN()" style="margin-bottom: 10px;">
                        <i class="fas fa-shield-alt"></i> SSL-VPN Kontrolü
                    </button>

                    <!-- Telnet/Port Kontrolü -->
                    <button class="btn btn-primary btn-block" onclick="openPortChecker()" style="margin-bottom: 10px;">
                        <i class="fas fa-network-wired"></i> Telnet/Port Kontrolü
                    </button>

                    <!-- Pingdom IP Kontrolü -->
                    <button class="btn btn-warning btn-block" onclick="monitoringChecker.checkIPs('pingdom')" style="margin-bottom: 10px; background-color: #FFD700; color: #000; border-color: #FFD700;">
                        <i class="fas fa-heartbeat"></i> Pingdom IP Kontrolü
                    </button>

                    <!-- Monitoring Dashboard -->
                    <a href="monitoring_dashboard.php" class="btn btn-block" style="margin-bottom: 10px; background: linear-gradient(135deg, #005588, #003d66); color: #fff; border: none;">
                        <i class="fas fa-tachometer-alt"></i> Monitoring Dashboard
                    </a>
                </div>
            </div>

            <?php if (!$readonly_mode): ?>
            <!-- Sistem Yönetimi -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-cog"></i> Sistem Yönetimi</h3>
                </div>
                <div class="card-body">
                    <p style="margin-bottom: 15px; font-size: 13px; color: #6c757d;">
                        Sistem durumu, kaynak yönetimi ve ayarlar
                    </p>
                    <a href="settings.php" class="btn btn-primary btn-block" style="margin-bottom: 10px;">
                        <i class="fas fa-cog"></i> Sistem Ayarları
                    </a>
                    <a href="sources_manager.php" class="btn btn-primary btn-block" style="margin-bottom: 10px;">
                        <i class="fas fa-cloud-download-alt"></i> Kaynak Yönetimi
                    </a>
                    <a href="status.php" class="btn btn-primary btn-block" style="margin-bottom: 10px;">
                        <i class="fas fa-tachometer-alt"></i> Durum ve Loglar
                    </a>
                </div>
            </div>

            <!-- Manuel Ekleme Formu -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-plus-circle"></i> Manuel Ekleme</h3>
                </div>
                <div class="card-body">
                    <p class="mb-3">Bir veya daha fazla IP adresi girin (örn: 192.168.1.1/24). Birden fazla giriş için virgül kullanın.</p>
                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                        <div class="form-group">
                            <label for="ip_address">IP Adresi:</label>
                            <input type="text" name="ip_address" id="ip_address" class="form-control" placeholder="IP Adresi">
                        </div>
                        
                        <div class="form-group">
                            <label for="comment">Yorum:</label>
                            <input type="text" name="comment" id="comment" class="form-control" placeholder="Yorum">
                        </div>
                        
                        <div class="form-group">
                            <label for="fqdn">FQDN:</label>
                            <input type="text" name="fqdn" id="fqdn" class="form-control" placeholder="FQDN">
                        </div>
                        
                        <div class="form-group">
                            <label for="jira">Jira Numarası/URL:</label>
                            <input type="text" name="jira" id="jira" class="form-control" placeholder="Jira Numarası/URL">
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Ekle
                        </button>
                    </form>
                </div>
            </div>

            <!-- Excel ile Toplu Ekleme -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-file-excel"></i> Excel ile Toplu Ekleme</h3>
                </div>
                <div class="card-body">
                    <p class="mb-3">Excel taslağını indirin, düzenleyin ve buraya yükleyin.</p>
                    <a href="download_excel.php" class="btn btn-success mb-3">
                        <i class="fas fa-download"></i> Excel Taslağını İndir
                    </a>
                    
                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
                        <div class="form-group">
                            <div class="file-upload">
                                <label for="excel_file" class="file-upload-label">
                                    <i class="fas fa-upload"></i> Dosya Seç
                                </label>
                                <input type="file" name="excel_file" id="excel_file" required onchange="updateFileName(this)">
                                <span id="file-name" class="file-name">Dosya seçilmedi</span>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary mt-2">
                            <i class="fas fa-cloud-upload-alt"></i> Yükle
                        </button>
                    </form>
                </div>
            </div>
            <?php endif; ?>
        </aside>
    </div>

    <!-- Onay Bekleyen IP'ler Bölümü -->
    <?php if (!$readonly_mode): ?>
    <div class="container" id="pending-ips-section" style="margin-top: 30px;">
        <div class="card">
            <div class="card-header" style="background-color: #fff3cd; border-bottom: 2px solid #ffc107;">
                <h2 class="card-title" style="color: #856404;">
                    <i class="fas fa-clock"></i> Onay Bekleyen IP'ler
                    <?php
                    $pending_ips_list = list_pending_ips();
                    $pending_count_display = count($pending_ips_list);
                    if ($pending_count_display > 0) {
                        echo "<span style='background-color: #dc3545; color: white; padding: 4px 10px; border-radius: 15px; font-size: 14px; margin-left: 10px;'>$pending_count_display</span>";
                    }
                    ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (count($pending_ips_list) > 0): ?>
                    <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin-bottom: 20px; border-radius: 4px;">
                        <strong><i class="fas fa-info-circle"></i> Bilgi:</strong>
                        Bu IP'ler hem whitelist'te hem de güvenlik listelerinde tespit edilmiştir.
                        Her IP için onay veya red kararı vermeniz gerekmektedir.
                    </div>

                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>IP Adresi</th>
                                    <th>Kaynak</th>
                                    <th>Tespit Tarihi</th>
                                    <th>İşlem</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($pending_ips_list as $pending_ip): ?>
                                    <tr>
                                        <td style="font-weight: bold; color: #005588;">
                                            <i class="fas fa-network-wired"></i> <?php echo htmlspecialchars($pending_ip['ip']); ?>
                                        </td>
                                        <td>
                                            <span style="background-color: #e9ecef; padding: 4px 8px; border-radius: 3px; font-size: 12px;">
                                                <?php echo htmlspecialchars(ucfirst($pending_ip['source'])); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($pending_ip['created_at']); ?></td>
                                        <td>
                                            <a href="approve_ip.php?token=<?php echo htmlspecialchars($pending_ip['id']); ?>"
                                               class="btn btn-warning btn-sm"
                                               target="_blank"
                                               style="font-size: 12px; padding: 5px 12px;">
                                                <i class="fas fa-external-link-alt"></i> Onay Sayfası
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div style="text-align: center; padding: 40px; color: #6c757d;">
                        <i class="fas fa-check-circle" style="font-size: 3rem; color: #28a745;"></i>
                        <p style="margin-top: 15px; font-size: 16px;">Onay bekleyen IP yok.</p>
                        <p style="font-size: 14px; color: #6c757d;">Tüm IP'ler işlenmiş durumda.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Spine Access Control Modal -->
    <div id="spineAccessModal" class="spine-modal">
        <div class="spine-modal-content">
            <div class="spine-modal-header">
                <h2>
                    <i class="fas fa-key"></i>
                    Spine-FW Erişim Kontrolü
                </h2>
                <button class="spine-modal-close" onclick="closeSpineModal()">&times;</button>
            </div>
            <div class="spine-modal-body">
                <div class="spine-info-box">
                    <p>
                        <strong><i class="fas fa-info-circle"></i> Bu araç ne işe yarar?</strong><br>
                        <strong>support.asseco-see.com.tr</strong> adresine erişim için Spine-FW üzerindeki
                        <strong>Policy ID 369</strong> kuralındaki <strong>Access_GRP-4431-4432</strong>
                        source address grubunda müşteri IP'sinin olup olmadığını kontrol eder.
                    </p>
                </div>

                <div class="spine-search-form">
                    <label for="spineSearchIp">
                        <i class="fas fa-network-wired"></i> Müşteri IP Adresi
                    </label>
                    <div class="spine-search-row">
                        <input type="text"
                               id="spineSearchIp"
                               class="spine-search-input"
                               placeholder="Örn: 192.168.1.100">
                        <button class="spine-search-btn" onclick="searchSpineIP()">
                            <i class="fas fa-search"></i> Kontrol Et
                        </button>
                    </div>
                </div>

                <div id="spineSearchResult"></div>

                <div class="spine-members-section">
                    <h3>
                        <i class="fas fa-list"></i>
                        Grup Üyeleri: Access_GRP-4431-4432
                        <span id="spineMemberCount" class="spine-member-count">Yükleniyor...</span>
                    </h3>

                    <input type="text"
                           id="spineMemberFilter"
                           class="spine-filter-input"
                           placeholder="Tablo içinde ara..."
                           onkeyup="filterSpineMembers()">

                    <div id="spineMembersTable">
                        <div class="spine-loading">
                            <i class="fas fa-spinner"></i>
                            <p>Grup üyeleri yükleniyor...</p>
                        </div>
                    </div>
                </div>

                <button class="spine-open-new-btn" onclick="openSpineInNewWindow()">
                    <i class="fas fa-external-link-alt"></i> Yeni Pencerede Aç
                </button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2024 cyberwebeyeos. Tüm hakları saklıdır.</p>
    </footer>

    <script>
        // Tüm onay kutularını seçme/kaldırma
        function toggleAllCheckboxes() {
            var checkboxes = document.getElementsByClassName('record-checkbox');
            var selectAllCheckbox = document.getElementById('select-all');

            for (var i = 0; i < checkboxes.length; i++) {
                checkboxes[i].checked = selectAllCheckbox.checked;
            }
        }

        // Dosya adını gösterme
        function updateFileName(input) {
            var fileName = input.files[0] ? input.files[0].name : 'Dosya seçilmedi';
            document.getElementById('file-name').textContent = fileName;
        }

        // Otomatik sayfa yenileme (isteğe bağlı - varsayılan kapalı)
        // Uncomment the following lines to enable auto-refresh every 60 seconds
        // setInterval(function() {
        //     location.reload();
        // }, 60000); // 60 saniye

        // Monitoring IP Checker'ı başlat
        document.addEventListener('DOMContentLoaded', function() {
            monitoringChecker = new MonitoringIPChecker('cyberwebeyeos');
        });

        // Kontrol Mekanizmaları Fonksiyonları

        // SSL-VPN Kontrolü
        function checkSSLVPN() {
            const width = 1400;
            const height = 900;
            const left = (screen.width - width) / 2;
            const top = (screen.height - height) / 2;

            window.open(
                '/cyberwebeyeos/ssl_vpn_monitor.php',
                'SSL-VPN Monitoring',
                `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
            );
        }

        // İnternet Kontrolü
        function checkInternet() {
            // Yeni pencerede açılacak kontrol arayüzü
            const width = 1400;
            const height = 900;
            const left = (screen.width - width) / 2;
            const top = (screen.height - height) / 2;

            window.open(
                '/cyberwebeyeos/internet_monitor.php',
                'İnternet Kontrolü',
                `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
            );
        }

        // Telnet/Port Kontrolü
        function openPortChecker() {
            const width = 650;
            const height = 700;
            const left = (screen.width - width) / 2;
            const top = (screen.height - height) / 2;

            window.open(
                '/cyberwebeyeos/check_port.php',
                'Port Kontrolü',
                `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
            );
        }

        // S2S VPN Tunnel Kontrolü
        function openVPNTunnelMonitor() {
            const width = 1400;
            const height = 900;
            const left = (screen.width - width) / 2;
            const top = (screen.height - height) / 2;

            window.open(
                '/cyberwebeyeos/vpn_tunnel_monitor.php',
                'S2S VPN Tunnel Kontrolü',
                `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
            );
        }

        // ========================================
        // Spine Access Control Modal Functions
        // ========================================

        let spineMembersData = [];

        // Modal açma
        function openSpineAccessControl() {
            document.getElementById('spineAccessModal').style.display = 'block';
            document.body.style.overflow = 'hidden';
            loadSpineMembers();
        }

        // Modal kapatma
        function closeSpineModal() {
            document.getElementById('spineAccessModal').style.display = 'none';
            document.body.style.overflow = 'auto';
            document.getElementById('spineSearchResult').innerHTML = '';
            document.getElementById('spineSearchIp').value = '';
        }

        // Modal dışına tıklama ile kapatma
        window.onclick = function(event) {
            var modal = document.getElementById('spineAccessModal');
            if (event.target == modal) {
                closeSpineModal();
            }
        }

        // ESC tuşu ile kapatma
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeSpineModal();
            }
        });

        // Grup üyelerini yükle
        function loadSpineMembers() {
            var tableDiv = document.getElementById('spineMembersTable');
            var countSpan = document.getElementById('spineMemberCount');

            tableDiv.innerHTML = '<div class="spine-loading"><i class="fas fa-spinner"></i><p>Grup üyeleri yükleniyor...</p></div>';

            fetch('/cyberwebeyeos/spine_access_control.php?ajax=1&action=get_members&group_name=Access_GRP-4431-4432')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        tableDiv.innerHTML = '<div class="spine-error-box"><i class="fas fa-exclamation-triangle"></i> ' + data.error + '</div>';
                        countSpan.textContent = 'Hata';
                        return;
                    }

                    spineMembersData = data.members || [];
                    countSpan.textContent = data.member_count + ' kayıt';

                    renderSpineMembersTable(spineMembersData);
                })
                .catch(error => {
                    tableDiv.innerHTML = '<div class="spine-error-box"><i class="fas fa-exclamation-triangle"></i> Bağlantı hatası: ' + error.message + '</div>';
                    countSpan.textContent = 'Hata';
                });
        }

        // Üye tablosunu oluştur
        function renderSpineMembersTable(members) {
            var tableDiv = document.getElementById('spineMembersTable');

            if (!members || members.length === 0) {
                tableDiv.innerHTML = '<p style="text-align: center; color: #6c757d;">Üye bulunamadı</p>';
                return;
            }

            var html = '<table class="spine-members-table" id="spineMembersTableInner">';
            html += '<thead><tr><th>#</th><th>Üye Adı</th><th>Tip</th><th>Değer</th></tr></thead>';
            html += '<tbody>';

            members.forEach(function(member, index) {
                var badgeClass = 'spine-badge-subnet';
                if (member.type === 'range') badgeClass = 'spine-badge-range';

                html += '<tr>';
                html += '<td>' + (index + 1) + '</td>';
                html += '<td>' + escapeHtml(member.name) + '</td>';
                html += '<td><span class="spine-badge ' + badgeClass + '">' + escapeHtml(member.type) + '</span></td>';
                html += '<td style="font-family: Courier New, monospace;">' + escapeHtml(member.value) + '</td>';
                html += '</tr>';
            });

            html += '</tbody></table>';
            tableDiv.innerHTML = html;
        }

        // Üye tablosu filtreleme
        function filterSpineMembers() {
            var input = document.getElementById('spineMemberFilter');
            var filter = input.value.toLowerCase();
            var table = document.getElementById('spineMembersTableInner');

            if (!table) return;

            var tr = table.getElementsByTagName('tr');

            for (var i = 1; i < tr.length; i++) {
                var td = tr[i].getElementsByTagName('td');
                var found = false;

                for (var j = 0; j < td.length; j++) {
                    if (td[j]) {
                        var txtValue = td[j].textContent || td[j].innerText;
                        if (txtValue.toLowerCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }

                tr[i].style.display = found ? '' : 'none';
            }
        }

        // IP arama
        function searchSpineIP() {
            var ipInput = document.getElementById('spineSearchIp');
            var resultDiv = document.getElementById('spineSearchResult');
            var searchBtn = document.querySelector('.spine-search-btn');
            var ip = ipInput.value.trim();

            if (!ip) {
                resultDiv.innerHTML = '<div class="spine-error-box"><i class="fas fa-exclamation-triangle"></i> Lütfen bir IP adresi girin.</div>';
                return;
            }

            // IP format kontrolü
            var ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipPattern.test(ip)) {
                resultDiv.innerHTML = '<div class="spine-error-box"><i class="fas fa-exclamation-triangle"></i> Geçersiz IP adresi formatı.</div>';
                return;
            }

            // Buton durumunu güncelle
            searchBtn.disabled = true;
            searchBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Kontrol ediliyor...';

            var formData = new FormData();
            formData.append('ip', ip);
            formData.append('group_name', 'Access_GRP-4431-4432');
            formData.append('policy_id', '369');

            fetch('/cyberwebeyeos/spine_access_control.php?ajax=1&action=search_ip', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                searchBtn.disabled = false;
                searchBtn.innerHTML = '<i class="fas fa-search"></i> Kontrol Et';

                if (data.error) {
                    resultDiv.innerHTML = '<div class="spine-error-box"><i class="fas fa-exclamation-triangle"></i> ' + escapeHtml(data.error) + '</div>';
                    return;
                }

                var html = '';
                if (data.found) {
                    html = '<div class="spine-result-box spine-result-found">';
                    html += '<div class="spine-result-header">';
                    html += '<i class="fas fa-check-circle" style="color: #28a745; font-size: 28px;"></i>';
                    html += '<span style="color: #155724;">IP Bu Grupta BULUNDU</span>';
                    html += '</div>';
                } else {
                    html = '<div class="spine-result-box spine-result-not-found">';
                    html += '<div class="spine-result-header">';
                    html += '<i class="fas fa-times-circle" style="color: #dc3545; font-size: 28px;"></i>';
                    html += '<span style="color: #721c24;">IP Bu Grupta BULUNAMADI</span>';
                    html += '</div>';
                }

                html += '<div class="spine-result-details">';
                html += '<table>';
                html += '<tr><td>Aranan IP:</td><td><strong>' + escapeHtml(data.ip) + '</strong></td></tr>';
                html += '<tr><td>Policy ID:</td><td>' + escapeHtml(data.policy_id) + '</td></tr>';
                html += '<tr><td>Policy Adı:</td><td>' + escapeHtml(data.policy_name || 'N/A') + '</td></tr>';
                html += '<tr><td>Address Group:</td><td>' + escapeHtml(data.group_name) + '</td></tr>';

                if (data.found && data.matches && data.matches.length > 0) {
                    html += '<tr><td>Eşleşen Kayıt:</td><td>';
                    data.matches.forEach(function(match) {
                        html += '<div style="margin-bottom: 5px;">';
                        html += '<strong>' + escapeHtml(match.member_name) + '</strong> ';
                        html += '(' + escapeHtml(match.type) + ': ' + escapeHtml(match.value) + ')';
                        html += '</div>';
                    });
                    html += '</td></tr>';
                }

                html += '</table>';
                html += '</div>';

                html += '<div style="margin-top: 15px; padding: 12px; background: rgba(0,0,0,0.05); border-radius: 6px;">';
                html += '<strong>Sonuç:</strong> ';
                if (data.found) {
                    html += '<span style="color: #155724;">Bu müşteri support.asseco-see.com.tr adresine erişebilir.</span>';
                } else {
                    html += '<span style="color: #721c24;">Bu müşteri support.asseco-see.com.tr adresine ERİŞEMEZ. IP\'nin gruba eklenmesi gerekiyor.</span>';
                }
                html += '</div>';

                html += '</div>';

                resultDiv.innerHTML = html;
            })
            .catch(error => {
                searchBtn.disabled = false;
                searchBtn.innerHTML = '<i class="fas fa-search"></i> Kontrol Et';
                resultDiv.innerHTML = '<div class="spine-error-box"><i class="fas fa-exclamation-triangle"></i> Bağlantı hatası: ' + escapeHtml(error.message) + '</div>';
            });
        }

        // Enter tuşu ile arama
        document.addEventListener('DOMContentLoaded', function() {
            var searchInput = document.getElementById('spineSearchIp');
            if (searchInput) {
                searchInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        searchSpineIP();
                    }
                });
            }
        });

        // Yeni pencerede aç
        function openSpineInNewWindow() {
            const width = 1000;
            const height = 800;
            const left = (screen.width - width) / 2;
            const top = (screen.height - height) / 2;

            window.open(
                '/cyberwebeyeos/spine_access_control.php',
                'Spine Erişim Kontrolü',
                `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
            );
        }

        // HTML escape fonksiyonu
        function escapeHtml(text) {
            if (!text) return '';
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>


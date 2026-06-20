<?php
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_role(['admin','operator']);
$file_path = "/var/www/html/blacklist.txt"; // Kara liste dosyası yolu
$output_file = "/var/www/html/cyberwebeyeosblacklist.txt"; // cyberwebeyeosblacklist.txt dosya yolu

// Seçilen IP'leri kontrol et
if (isset($_POST['selected_ips']) && !empty($_POST['selected_ips'])) {
    $selected_ips = $_POST['selected_ips'];
    // Kara liste dosyasını oku
    $file_content = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $new_content = [];
    // Seçilen IP'leri kara liste dosyasından çıkar
    foreach ($file_content as $line) {
        list($ip, $comment, $date, $fqdn, $jira) = explode("|", $line);
        if (!in_array(trim($ip), $selected_ips)) {
            $new_content[] = $line; // Seçilen IP değilse yeni içeriğe ekle
        }
    }
    // Yeni içeriği kara liste dosyasına yaz
    file_put_contents($file_path, implode("\n", $new_content));
    
    // cyberwebeyeosblacklist.txt dosyasını güncelle
    $blacklist_entries = array_map(function($line) {
        list($ip, $comment, $date, $fqdn, $jira) = explode("|", $line);
        return !empty(trim($ip)) && trim($ip) != 'N/A' ? trim($ip) : 
               (!empty(trim($fqdn)) ? trim($fqdn) : '');
    }, $new_content);
    
    $all_entries = $blacklist_entries;

    // Boş değerleri filtrele ve tekrarlananları kaldır
    $all_entries = array_filter(array_unique($all_entries));
    
    // Cyberwebeyeos blacklist dosyasını oluştur
    file_put_contents($output_file, implode("\n", $all_entries));
    
    $_SESSION['message'] = "Seçilen IP adresleri başarıyla silindi.";
} else {
    $_SESSION['message'] = "Silinecek IP adresi seçilmedi.";
}

// IP'yi CIDR formatında doğrulama (cyberwebeyeosblacklist.php'den kopyalandı)
function validate_cidr($cidr) {
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d+$/', $cidr)) {
        list($ip, $prefix) = explode('/', $cidr);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
        }
    }
    return false;
}

// Yönlendirme
header("Location: cyberwebeyeosblacklistadmin.php");
exit();
?>
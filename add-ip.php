<?php
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_role(['admin','operator']);
// Hata ayıklama
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Veri doğrulama fonksiyonları
function validateIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $parts = explode('.', $ip);
        foreach ($parts as $part) {
            if (intval($part) > 255 || intval($part) < 0) {
                return false;
            }
        }
        return true;
    }
    return false;
}

function validateFQDN($fqdn) {
    return preg_match('/^(?=.{1,255}$)[a-zA-Z0-9][a-zA-Z0-9-]{1,63}(.[a-zA-Z0-9-]{1,63})*$/', $fqdn);
}

function validateURL($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

// DNS bilgisi alma fonksiyonu
function getDNSInfo($ip) {
    $dns = gethostbyaddr($ip);
    return $dns ? $dns : 'Bilinmiyor';
}

// IP bilgilerini almak için API'yi sorgulayan fonksiyon
function getIPInfo($ip) {
    // R87b: Key auth_config.php vault'tan okunur (greynoise.php pattern'i).
    $ipgeolocation_api_key = '';
    $cfg = __DIR__ . '/auth_config.php';
    if (file_exists($cfg)) { @include $cfg; }
    $apiKey = (string)($ipgeolocation_api_key ?? '');
    if ($apiKey === '') { return []; }
    $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$apiKey&ip=$ip";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    $data = json_decode($response, true);
    return $data;
}

// Kara listede eklenen öğeleri görüntüleme fonksiyonu
function display_blacklist() {
    $file_path = __DIR__ . '/blacklist.txt';
    if (!file_exists($file_path)) {
        echo "<div class='alert alert-danger'>Kara liste bulunamadı.</div>";
        return;
    }

    $file_content = file_get_contents($file_path);
    if ($file_content === false) {
        echo "<div class='alert alert-danger'>Dosya okunamadı!</div>";
        return;
    }

    $items = explode("\n", $file_content);
    echo "<h2>Kara Liste</h2>";
    echo "<table border='1'>";
    echo "<tr><th>IP Adresi</th><th>ASN</th><th>CIDR</th><th>NetName</th><th>DNS Bilgisi</th></tr>";
    foreach ($items as $item) {
        $ipInfo = getIPInfo($item);
        $asn = isset($ipInfo['asn']) ? $ipInfo['asn'] : 'N/A';
        $cidr = isset($ipInfo['cidr']) ? $ipInfo['cidr'] : 'N/A';
        $netName = isset($ipInfo['netname']) ? $ipInfo['netname'] : 'N/A';
        $dns = getDNSInfo($item);
        echo "<tr><td>$item</td><td>$asn</td><td>$cidr</td><td>$netName</td><td>$dns</td></tr>";
    }
    echo "</table>";
}

// Kara listeye öğe ekleme fonksiyonu
function add_to_blacklist($item) {
    $file_path = __DIR__ . '/blacklist.txt';

    if (!file_exists($file_path)) {
        echo "<div class='alert alert-danger'>Kara liste dosyası bulunamadı!</div>";
        return;
    }

    $items = file($file_path, FILE_IGNORE_NEW_LINES);
    if (in_array($item, $items)) {
        echo "<div class='alert alert-warning'>$item zaten kara listede!</div>";
        return;
    }

    $result = file_put_contents($file_path, $item . PHP_EOL, FILE_APPEND | LOCK_EX);
    if ($result === false) {
        echo "<div class='alert alert-danger'>Öğe kara listeye eklenemedi!</div>";
        return;
    }

    echo "<div class='alert alert-success alert-dismissible'>Öğe başarıyla kara listeye eklendi: $item<button type='button' class='close' data-dismiss='alert'>&times;</button></div>";
}

// Excel dosyasını işleme fonksiyonu
function process_excel_file($file_tmp_name) {
    require_once __DIR__ . '/vendor/autoload.php'; // PhpSpreadsheet kütüphanesi yükle
    $reader = new \PhpOffice\PhpSpreadsheet\Reader\Xlsx();
    $spreadsheet = $reader->load($file_tmp_name);
    $worksheet = $spreadsheet->getActiveSheet();

    foreach ($worksheet->getRowIterator() as $row) {
        foreach ($row->getCellIterator() as $cell) {
            $item = trim($cell->getValue()); // Veriyi temizle
            if (!empty($item)) {
                if (validateIP($item) || validateFQDN($item) || validateURL($item)) {
                    add_to_blacklist($item);
                } else {
                    echo "<div class='alert alert-danger'>Geçersiz öğe: $item</div>";
                }
            }
        }
    }
}

// Kara listede arama yapma fonksiyonu
function search_in_blacklist($search_item) {
    $file_path = __DIR__ . '/blacklist.txt';
    if (!file_exists($file_path)) {
        return [];
    }

    $items = file($file_path, FILE_IGNORE_NEW_LINES);
    $search_results = [];
    foreach ($items as $item) {
        if (stripos($item, $search_item) !== false) {
            $search_results[] = $item;
        }
    }
    return $search_results;
}

// Manuel Ekleme veya Excel Dosyası Yükleme
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!empty($_POST['ip_address'])) {
        $item = $_POST['ip_address'];
        if (validateIP($item)) {
            add_to_blacklist($item);
        } else {
            echo "<div class='alert alert-danger'>Geçersiz IP adresi!</div>";
        }
    } elseif (!empty($_POST['fqdn'])) {
        $item = $_POST['fqdn'];
        if (validateFQDN($item)) {
            add_to_blacklist($item);
        } else {
            echo "<div class='alert alert-danger'>Geçersiz FQDN!</div>";
        }
    } elseif (!empty($_POST['url'])) {
        $item = $_POST['url'];
        if (validateURL($item)) {
            add_to_blacklist($item);
        } else {
            echo "<div class='alert alert-danger'>Geçersiz URL!</div>";
        }
    } elseif (!empty($_FILES['excel_file']['name'])) {
        process_excel_file($_FILES['excel_file']['tmp_name']);
    } elseif (!empty($_POST['search_item'])) {
        $search_item = $_POST['search_item'];
        $search_results = search_in_blacklist($search_item);
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>IP Kara Listesi</title>
    <style>
        /* Bildirimler için stil */
        .alert {
            position: fixed;
            right: 20px;
            z-index: 9999;
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            animation: fadein 0.5s, fadeout 0.5s 2.5s;
        }
.close {
            color: #000;
            float: right;
            font-size: 20px;
            font-weight: bold;
            line-height: 1;
            cursor: pointer;
            background-color: transparent;
            border: 0;
            -webkit-appearance: none;
        }

        /* Renkli bildirim stilleri */
        .alert-success {
            color: #3c763d;
            background-color: #dff0d8;
            border-color: #d6e9c6;
        }
        .alert-warning {
            color: #8a6d3b;
            background-color: #fcf8e3;
            border-color: #faebcc;
        }
        .alert-danger {
            color: #a94442;
            background-color: #f2dede;
            border-color: #ebccd1;
        }
        .alert-info {
            color: #31708f;
            background-color: #d9edf7;
            border-color: #bce8f1;
        }

        /* Animasyonlar */
        @keyframes fadein {
            from {opacity: 0;}
            to {opacity: 1;}
        }
        @keyframes fadeout {
            from {opacity: 1;}
            to {opacity: 0;}
        }
    </style>
</head>
<body>
    <h1>IP Kara Listesi</h1>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
        <h2>Manuel Ekleme</h2>
        <label for="ip_address">IP Adresi (Örneğin: 192.168.1.1):</label>
        <input type="text" name="ip_address" id="ip_address" placeholder="IP Adresi">
        <br>
        <label for="fqdn">FQDN (Örneğin: example.com):</label>
        <input type="text" name="fqdn" id="fqdn" placeholder="FQDN">
        <br>
        <label for="url">URL (Örneğin: http://www.example.com):</label>
        <input type="text" name="url" id="url" placeholder="URL">
        <br>
        <input type="submit" value="Ekle">
    </form>

    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
        <h2>Excel Dosyası Yükleme</h2>
        <label for="excel_file">Excel Dosyası (Dosya uzantısı .xlsx olmalıdır):</label>
        <input type="file" name="excel_file" id="excel_file" accept=".xlsx">
        <br>
        <input type="submit" value="Yükle">
    </form>

    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <h2>Arama</h2>
        <label for="search_item">Aranacak Öğe:</label>
        <input type="text" name="search_item" id="search_item">
        <input type="submit" value="Ara">
    </form>

    <?php
    if (!empty($search_results)) {
        echo '<div class="search-results">';
        echo '<h2>Arama Sonuçları</h2>';
        echo '<ul>';
        foreach ($search_results as $result) {
            echo "<li>$result</li>";
        }
        echo '</ul>';
        echo '</div>';
    }
    ?>

    <?php display_blacklist(); ?>

    <script>
        // Kapanabilir bildirimler için JavaScript
        document.addEventListener("DOMContentLoaded", function() {
            let alertOffset = 20;

            document.addEventListener("click", function(event) {
                if (event.target.classList.contains('close')) {
                    event.target.parentElement.style.display = 'none';
                }
            });

            document.querySelectorAll('.alert').forEach(function(alert) {
                alert.style.top = alertOffset + 'px';
                alertOffset += alert.offsetHeight + 20;
                setTimeout(function() {
                    alert.style.display = 'none';
                }, 30000); // 30 saniye sonra gizle
            });
        });
    </script>
</body>
</html>

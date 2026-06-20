<?php
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_once __DIR__ . '/ioc_helpers.php';
require_role(['admin','operator']);
$file_path = "/var/www/html/blacklist.txt";

// IP adresini almak
$ip_to_edit = isset($_GET['ip']) ? trim($_GET['ip']) : '';
$existing_entry = '';

if ($ip_to_edit) {
    $content = file($file_path);
    foreach ($content as $line) {
        if (strpos($line, $ip_to_edit) !== false) {
            $existing_entry = $line;
            break;
        }
    }
    if (!$existing_entry) {
        die("Giriş bulunamadı.");
    }
    // R28 (T1.2): 10-field parse via ioc_helpers
    $existing = cwe_parse_blacklist_entry($existing_entry);
    $ip = $existing['value']; $comment = $existing['comment']; $date = $existing['date'];
    $fqdn = $existing['fqdn']; $jira = $existing['jira']; $tlp = $existing['tlp'];
    $existing_type = $existing['type'];
    $existing_conf = $existing['confidence'];
    $existing_vu = $existing['valid_until'];
} else {
    die("IP adresi belirtilmemiş.");
}

// IP güncelleme işlemi
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $ip = isset($_POST['ip_address']) ? trim($_POST['ip_address']) : 'N/A';
    $comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
    $fqdn = isset($_POST['fqdn']) ? trim($_POST['fqdn']) : '';
    $jira = isset($_POST['jira']) ? trim($_POST['jira']) : '';
    $tlp = strtoupper(trim($_POST['tlp'] ?? 'WHITE'));
    if (!in_array($tlp, ['RED','AMBER','GREEN','WHITE'], true)) $tlp = 'WHITE';
    $type_in = strtolower(trim($_POST['type'] ?? ''));
    if (!in_array($type_in, CWE_IOC_TYPES, true)) $type_in = cwe_detect_type($ip);
    $conf_in = max(0, min(100, (int)($_POST['confidence'] ?? 75)));
    $vu_in = trim($_POST['valid_until'] ?? 'permanent');
    if ($vu_in !== 'permanent') {
        $ts = strtotime($vu_in);
        $vu_in = $ts ? date('Y-m-d H:i:s', $ts) : 'permanent';
    }

    // IP doğrulama
    if ($ip !== 'N/A') {
        $ip_with_prefix = convert_ip_to_prefix($ip);
        if (!validate_ip($ip_with_prefix)) {
            $error_message = "Geçersiz IP adresi veya subnet prefix: $ip.";
        }
    } else {
        $ip_with_prefix = 'N/A'; // N/A olduğunda direkt ayarla
    }

    if (!isset($error_message)) {
        $date_new = date('Y-m-d H:i:s');
        // R28 (T1.2): 10-field schema yaz; created date orijinal kalır
        $entry_arr = [
            'value' => $ip_with_prefix, 'comment' => $comment,
            'date' => $existing['date'] ?: $date_new,
            'fqdn' => $fqdn, 'jira' => $jira, 'tlp' => $tlp,
            'type' => $type_in,
            'added_by' => $existing['added_by'] ?: cwe_current_user(),
            'confidence' => $conf_in, 'valid_until' => $vu_in,
        ];
        $new_entry = cwe_format_blacklist_entry($entry_arr) . "\n";

        $content = file($file_path);
        foreach ($content as &$line) {
            if (strpos($line, $ip_to_edit) !== false) {
                $line = $new_entry;
                break;
            }
        }
        file_put_contents($file_path, implode("", $content));
        audit_log_event('blacklist_edit', ['entry'=>$ip_with_prefix, 'tlp'=>$tlp, 'type'=>$type_in, 'confidence'=>$conf_in, 'valid_until'=>$vu_in]);
        $_SESSION['message'] = "Giriş güncellendi. (TLP $tlp · tip $type_in · conf $conf_in · süre $vu_in)";
        header('Location: cyberwebeyeosblacklistadmin.php');
        exit();
    }
}

// IP adresini prefix formatına çevir
function convert_ip_to_prefix($ip) {
    if ($ip !== 'N/A' && strpos($ip, '/') === false) {
        return "$ip/32"; // Varsayılan olarak /32 ekle
    }
    return $ip; // Eğer N/A veya zaten prefix varsa, olduğu gibi döndür
}

// IP doğrulama
function validate_ip($ip) {
    // Geçerli IP ve subnet prefix kontrolü
    return preg_match('/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/[0-9]{1,2})?$|^(?:255\.255\.255\.255)$/', $ip) && validate_subnet($ip);
}

// Subnet doğrulama
function validate_subnet($ip) {
    // Subnet prefix kontrolü: max /32
    if (strpos($ip, '/') !== false) {
        $parts = explode('/', $ip);
        $prefix = intval($parts[1]);
        return $prefix >= 0 && $prefix <= 32; // /0 ile /32 arasında olmalı
    }
    return true; // Eğer subnet yoksa, geçerli sayılır
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>IP Güncelle</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
        <h1>Cyberwebeyeos Blacklist Yönetim Arayüzü</h1>
    </header>

    <main>
        <div class="notification-area">
            <?php
            if (isset($error_message)) {
                echo "<div class='alert alert-danger'>{$error_message}</div>";
            }
            if (isset($_SESSION['message'])) {
                echo "<div class='alert'>{$_SESSION['message']}</div>";
                unset($_SESSION['message']);
            }
            ?>
        </div>
        <div class="container">
            <h1>IP Güncelle</h1>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"] . "?ip=$ip_to_edit"); ?>" method="post">
                <label for="ip_address">IP Adresi:</label>
                <input type="text" name="ip_address" id="ip_address" value="<?php echo htmlspecialchars($ip); ?>">
                <label for="comment">Yorum:</label>
                <input type="text" name="comment" id="comment" value="<?php echo htmlspecialchars($comment); ?>">
                <label for="fqdn">FQDN:</label>
                <input type="text" name="fqdn" id="fqdn" value="<?php echo htmlspecialchars($fqdn); ?>">
                <label for="jira">Jira Numarası/URL:</label>
                <input type="text" name="jira" id="jira" value="<?php echo htmlspecialchars($jira); ?>">
                <label for="tlp">TLP:</label>
                <select name="tlp" id="tlp">
                    <option value="WHITE" <?= $tlp==='WHITE'?'selected':'' ?>>⚪ WHITE — sınırsız</option>
                    <option value="GREEN" <?= $tlp==='GREEN'?'selected':'' ?>>🟢 GREEN — topluluk</option>
                    <option value="AMBER" <?= $tlp==='AMBER'?'selected':'' ?>>🟡 AMBER — organizasyon</option>
                    <option value="RED"   <?= $tlp==='RED'  ?'selected':'' ?>>🔴 RED — sadece alıcı</option>
                </select>
                <label for="type">IoC Tipi:</label>
                <select name="type" id="type">
                    <?php foreach (CWE_IOC_TYPES as $t): ?>
                        <option value="<?= $t ?>" <?= $existing_type===$t?'selected':'' ?>><?= $t ?></option>
                    <?php endforeach; ?>
                </select>
                <label for="confidence">Güven Skoru (0-100):</label>
                <input type="number" name="confidence" id="confidence" min="0" max="100" step="1" value="<?= (int)$existing_conf ?>">
                <label for="valid_until">Süre Bitiş (ISO veya 'permanent'):</label>
                <input type="text" name="valid_until" id="valid_until" value="<?= htmlspecialchars($existing_vu) ?>" placeholder="2026-12-31 23:59:59 veya permanent">
                <label for="date">Oluşturulma Tarihi:</label>
                <input type="text" name="date" id="date" value="<?php echo htmlspecialchars($date); ?>" readonly>
                <input type="submit" value="Güncelle">
            </form>
        </div>
    </main>

    <footer>
        <p>&copy; 2024 Cyberwebeyeos. Tüm hakları saklıdır.</p>
    </footer>
</body>
</html>

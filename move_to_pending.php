<?php
/**
 * Mevcut combined file'daki bir IP'yi pending hale getirir ve dosyadan kaldırır
 */

require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_role(['admin','operator']);
error_reporting(E_ALL);
ini_set('display_errors', 1);
header('Content-Type: text/html; charset=utf-8');

require_once 'pending_ips_helper.php';

$message = "";
$message_type = "";

// IP taşıma işlemi
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ip']) && isset($_POST['source'])) {
    $ip = trim($_POST['ip']);
    $source = trim($_POST['source']);

    if (empty($ip)) {
        $message = "IP adresi boş olamaz!";
        $message_type = "danger";
    } else {
        // IP'yi pending'e ekle
        $token = add_pending_ip($ip, $source);

        if ($token) {
            // IP'yi combined file'dan kaldır
            $combined_file = '/var/www/html/cyberwebeyeosblacklist.txt';
            if (file_exists($combined_file)) {
                $lines = file($combined_file, FILE_IGNORE_NEW_LINES);
                $new_lines = [];
                $removed = false;

                foreach ($lines as $line) {
                    $line = trim($line);
                    if (empty($line)) continue;

                    // IP'yi karşılaştır (CIDR notasyonu ile)
                    $line_ip = explode('/', $line)[0];
                    $search_ip = explode('/', $ip)[0];

                    if ($line_ip !== $search_ip) {
                        $new_lines[] = $line;
                    } else {
                        $removed = true;
                    }
                }

                if ($removed) {
                    file_put_contents($combined_file, implode("\n", $new_lines) . "\n");
                    $message = "IP adresi başarıyla pending durumuna alındı ve blacklist.txt'den kaldırıldı. Onay linki: <a href='approve_ip.php?token=$token' target='_blank'>approve_ip.php?token=$token</a>";
                    $message_type = "success";
                } else {
                    $message = "IP adresi combined file'da bulunamadı, ancak pending listesine eklendi.";
                    $message_type = "warning";
                }
            } else {
                $message = "Combined file bulunamadı!";
                $message_type = "danger";
            }
        } else {
            $message = "IP pending listesine eklenirken hata oluştu!";
            $message_type = "danger";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP'yi Pending'e Taşı - Cyberwebeyeos</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
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

        .header {
            background: linear-gradient(135deg, var(--primary-color), #003c6c);
            color: white;
            padding: 1rem;
            box-shadow: 0 2px 5px var(--shadow-color);
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

        .logo {
            height: 40px;
        }

        .container {
            max-width: 800px;
            margin: 40px auto;
            padding: 0 15px;
        }

        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px var(--shadow-color);
            overflow: hidden;
            margin-bottom: 20px;
        }

        .card-header {
            padding: 20px;
            background-color: #f8f9fa;
            border-bottom: 1px solid var(--border-color);
        }

        .card-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--secondary-color);
            margin: 0;
        }

        .card-body {
            padding: 30px;
        }

        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
            font-weight: 500;
        }

        .alert-danger {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }

        .alert-success {
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }

        .alert-warning {
            color: #856404;
            background-color: #fff3cd;
            border-color: #ffeaa7;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--secondary-color);
        }

        .form-control {
            width: 100%;
            padding: 10px 12px;
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

        .btn {
            display: inline-block;
            font-weight: 500;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            user-select: none;
            border: 1px solid transparent;
            padding: 10px 20px;
            font-size: 14px;
            line-height: 1.5;
            border-radius: 4px;
            transition: all 0.15s ease-in-out;
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

        .btn-secondary {
            color: #fff;
            background-color: #6c757d;
            border-color: #6c757d;
        }

        .btn-secondary:hover {
            background-color: #5a6268;
            border-color: #545b62;
        }

        .description-box {
            background-color: #d1ecf1;
            border-left: 4px solid var(--info-color);
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }

        .description-box h4 {
            margin-bottom: 10px;
            color: #0c5460;
        }

        .btn-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .footer {
            padding: 15px;
            text-align: center;
            background-color: var(--dark-color);
            color: white;
            margin-top: 40px;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <h1 class="header-title">IP'yi Pending'e Taşı</h1>
            <img src="/images/cyberwebeyeos.png" alt="Cyberwebeyeos Logo" class="logo">
        </div>
    </header>

    <div class="container">
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Blacklist'teki IP'yi Onay Sürecine Al</h2>
            </div>
            <div class="card-body">
                <?php if (!empty($message)): ?>
                    <div class="alert alert-<?php echo htmlspecialchars($message_type); ?>">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>

                <div class="description-box">
                    <h4><i class="fas fa-info-circle"></i> Bilgi</h4>
                    <p>Bu araç, şu anda combined blacklist dosyasında bulunan bir IP adresini <strong>bekleyen (pending)</strong> durumuna alır ve dosyadan kaldırır.</p>
                    <p style="margin-top: 10px;">Bu işlem sonrasında IP için bir onay linki oluşturulacak ve mail ile bildirim yapılabilir.</p>
                </div>

                <form method="post">
                    <div class="form-group">
                        <label class="form-label" for="ip">IP Adresi</label>
                        <input type="text" class="form-control" id="ip" name="ip" placeholder="Örnek: 31.223.41.199" required>
                        <small style="color: #6c757d; display: block; margin-top: 5px;">
                            IP adresini CIDR notasyonu ile veya normal olarak girebilirsiniz (örn: 1.2.3.4 veya 1.2.3.4/32)
                        </small>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="source">Kaynak</label>
                        <select class="form-control" id="source" name="source" required>
                            <option value="">Kaynak seçin...</option>
                            <option value="cinsscore">Cinsscore</option>
                            <option value="manual">Manuel</option>
                        </select>
                    </div>

                    <div class="btn-group">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-exchange-alt"></i> Pending'e Taşı
                        </button>
                        <a href="cyberwebeyeosblacklistadmin.php" class="btn btn-secondary">
                            <i class="fas fa-arrow-left"></i> Admin Paneline Dön
                        </a>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2024 Cyberwebeyeos. Tüm hakları saklıdır.</p>
    </footer>
</body>
</html>

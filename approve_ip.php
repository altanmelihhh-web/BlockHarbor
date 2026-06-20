<?php
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';
require_role(['admin','operator']);
error_reporting(E_ALL);
ini_set('display_errors', 1);
header('Content-Type: text/html; charset=utf-8');

require_once 'pending_ips_helper.php';

$message = "";
$message_type = "";
$pending_ip = null;
$token = isset($_GET['token']) ? trim($_GET['token']) : '';

// Token kontrolü
if (empty($token)) {
    $message = "Geçersiz erişim! Token parametresi eksik.";
    $message_type = "danger";
} else {
    $pending_ip = get_pending_ip_by_token($token);

    if ($pending_ip === null) {
        $message = "Token bulunamadı veya geçersiz!";
        $message_type = "danger";
    } elseif ($pending_ip['status'] !== 'pending') {
        // Zaten işlenmiş
        if ($pending_ip['status'] === 'approved') {
            $message = "Bu IP adresi daha önce blacklist'e eklenmiş.";
            $message_type = "info";
        } elseif ($pending_ip['status'] === 'rejected') {
            $message = "Bu IP adresi daha önce bypass edilmiş (eklenmemiş).";
            $message_type = "info";
        }
    }
}

// Session'dan mesajları al
if (isset($_SESSION['message']) && isset($_SESSION['message_type'])) {
    $message = $_SESSION['message'];
    $message_type = $_SESSION['message_type'];
    unset($_SESSION['message']);
    unset($_SESSION['message_type']);
}

// Onay/Red işlemleri
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $pending_ip !== null && $pending_ip['status'] === 'pending') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] === 'approve') {
            if (approve_pending_ip($token)) {
                $_SESSION['message'] = "IP adresi başarıyla blacklist'e eklendi.";
                $_SESSION['message_type'] = "success";
            } else {
                $_SESSION['message'] = "IP onaylanırken bir hata oluştu.";
                $_SESSION['message_type'] = "danger";
            }
        } elseif ($_POST['action'] === 'reject') {
            if (reject_pending_ip($token)) {
                $_SESSION['message'] = "IP adresi bypass edildi. Blacklist'e eklenmeyecek.";
                $_SESSION['message_type'] = "success";
            } else {
                $_SESSION['message'] = "IP reddedilirken bir hata oluştu.";
                $_SESSION['message_type'] = "danger";
            }
        }

        // POST-Redirect-GET pattern: İşlem sonrası sayfayı yenile
        header("Location: approve_ip.php?token=" . urlencode($token));
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Onay Sistemi - Cyberwebeyeos</title>
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

        .alert-info {
            color: #0c5460;
            background-color: #d1ecf1;
            border-color: #bee5eb;
        }

        .alert-warning {
            color: #856404;
            background-color: #fff3cd;
            border-color: #ffeaa7;
        }

        .ip-info {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .ip-info-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
        }

        .ip-info-row:last-child {
            border-bottom: none;
        }

        .ip-info-label {
            font-weight: 600;
            color: var(--secondary-color);
        }

        .ip-info-value {
            color: #495057;
        }

        .ip-address-display {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary-color);
            text-align: center;
            padding: 20px;
            background-color: #e9ecef;
            border-radius: 5px;
            margin: 20px 0;
        }

        .btn-group {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
        }

        .btn {
            display: inline-block;
            font-weight: 500;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            user-select: none;
            border: 1px solid transparent;
            padding: 12px 30px;
            font-size: 16px;
            line-height: 1.5;
            border-radius: 4px;
            transition: all 0.15s ease-in-out;
            cursor: pointer;
            text-decoration: none;
        }

        .btn i {
            pointer-events: none;
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .btn-success {
            color: #fff;
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .btn-success:hover:not(:disabled) {
            background-color: #218838;
            border-color: #1e7e34;
        }

        .btn-danger {
            color: #fff;
            background-color: var(--danger-color);
            border-color: var(--danger-color);
        }

        .btn-danger:hover:not(:disabled) {
            background-color: #c82333;
            border-color: #bd2130;
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

        .description-box {
            background-color: #fff3cd;
            border-left: 4px solid var(--warning-color);
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }

        .description-box h4 {
            margin-bottom: 10px;
            color: #856404;
        }

        .description-box ul {
            margin-left: 20px;
        }

        .description-box li {
            margin-bottom: 5px;
        }

        .footer {
            padding: 15px;
            text-align: center;
            background-color: var(--dark-color);
            color: white;
            margin-top: 40px;
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .btn-group {
                flex-direction: column;
            }

            .btn {
                width: 100%;
            }

            .ip-info-row {
                flex-direction: column;
                gap: 5px;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <h1 class="header-title">IP Onay Sistemi</h1>
            <img src="/images/cyberwebeyeos.png" alt="Cyberwebeyeos Logo" class="logo">
        </div>
    </header>

    <div class="container">
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Whitelist-Blacklist Çakışması Onay</h2>
            </div>
            <div class="card-body">
                <?php if (!empty($message)): ?>
                    <div class="alert alert-<?php echo htmlspecialchars($message_type); ?>">
                        <?php echo htmlspecialchars($message); ?>
                    </div>
                <?php endif; ?>

                <?php if ($pending_ip !== null && $pending_ip['status'] === 'pending'): ?>
                    <div class="description-box">
                        <h4><i class="fas fa-exclamation-triangle"></i> Uyarı!</h4>
                        <p>Aşağıdaki IP adresi hem <strong>Whitelist</strong>'te hem de <strong><?php echo htmlspecialchars(ucfirst($pending_ip['source'])); ?></strong> güvenlik listesinde tespit edilmiştir.</p>
                        <p style="margin-top: 10px;"><strong>Lütfen aşağıdaki seçeneklerden birini seçin:</strong></p>
                        <ul>
                            <li><strong>Blacklist'e Ekle:</strong> Bu IP'nin tehdit olduğunu onaylıyorsanız ve blacklist'e eklenmesini istiyorsanız.</li>
                            <li><strong>Bypass Et:</strong> Bu IP'nin güvenli olduğunu düşünüyorsanız ve whitelist'te kalmasını istiyorsanız.</li>
                        </ul>
                    </div>

                    <div class="ip-address-display">
                        <i class="fas fa-network-wired"></i> <?php echo htmlspecialchars($pending_ip['ip']); ?>
                    </div>

                    <div class="ip-info">
                        <div class="ip-info-row">
                            <span class="ip-info-label">Kaynak Liste:</span>
                            <span class="ip-info-value"><?php echo htmlspecialchars(ucfirst($pending_ip['source'])); ?></span>
                        </div>
                        <div class="ip-info-row">
                            <span class="ip-info-label">Tespit Tarihi:</span>
                            <span class="ip-info-value"><?php echo htmlspecialchars($pending_ip['created_at']); ?></span>
                        </div>
                        <div class="ip-info-row">
                            <span class="ip-info-label">Durum:</span>
                            <span class="ip-info-value">Onay Bekliyor</span>
                        </div>
                    </div>

                    <form method="post" action="" id="approvalForm">
                        <div class="btn-group">
                            <button type="submit" name="action" value="approve" class="btn btn-success">
                                <i class="fas fa-check-circle"></i> Blacklist'e Ekle
                            </button>
                            <button type="submit" name="action" value="reject" class="btn btn-danger">
                                <i class="fas fa-times-circle"></i> Bypass Et (Ekleme)
                            </button>
                        </div>
                    </form>
                <?php elseif ($pending_ip !== null): ?>
                    <div class="ip-address-display">
                        <i class="fas fa-network-wired"></i> <?php echo htmlspecialchars($pending_ip['ip']); ?>
                    </div>

                    <div class="ip-info">
                        <div class="ip-info-row">
                            <span class="ip-info-label">Kaynak Liste:</span>
                            <span class="ip-info-value"><?php echo htmlspecialchars(ucfirst($pending_ip['source'])); ?></span>
                        </div>
                        <div class="ip-info-row">
                            <span class="ip-info-label">Tespit Tarihi:</span>
                            <span class="ip-info-value"><?php echo htmlspecialchars($pending_ip['created_at']); ?></span>
                        </div>
                        <div class="ip-info-row">
                            <span class="ip-info-label">Durum:</span>
                            <span class="ip-info-value">
                                <?php
                                if ($pending_ip['status'] === 'approved') {
                                    echo '<span style="color: var(--success-color);"><i class="fas fa-check"></i> Onaylandı</span>';
                                } else {
                                    echo '<span style="color: var(--danger-color);"><i class="fas fa-times"></i> Bypass Edildi</span>';
                                }
                                ?>
                            </span>
                        </div>
                    </div>

                    <div style="text-align: center; margin-top: 20px;">
                        <a href="cyberwebeyeosblacklistadmin.php" class="btn btn-primary">
                            <i class="fas fa-arrow-left"></i> Admin Paneline Dön
                        </a>
                    </div>
                <?php else: ?>
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-exclamation-circle" style="font-size: 4rem; color: var(--danger-color);"></i>
                        <p style="margin-top: 20px; font-size: 1.1rem;">Geçersiz veya süresi dolmuş token.</p>
                        <a href="cyberwebeyeosblacklistadmin.php" class="btn btn-primary" style="margin-top: 20px;">
                            <i class="fas fa-home"></i> Admin Paneline Dön
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2024 Cyberwebeyeos. Tüm hakları saklıdır.</p>
    </footer>

    <script>
        // Form gönderiminde visual feedback
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('approvalForm');
            if (form) {
                const buttons = form.querySelectorAll('button[type="submit"]');

                buttons.forEach(function(button) {
                    button.addEventListener('click', function(e) {
                        const actionValue = this.getAttribute('value');

                        // Tüm butonları devre dışı bırak
                        buttons.forEach(function(btn) {
                            btn.disabled = true;
                        });

                        // Tıklanan butona göre mesaj göster
                        if (actionValue === 'approve') {
                            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Blacklist\'e ekleniyor...';
                            this.style.backgroundColor = '#1e7e34';
                        } else if (actionValue === 'reject') {
                            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Bypass ediliyor...';
                            this.style.backgroundColor = '#bd2130';
                        }
                    });
                });
            }
        });
    </script>
</body>
</html>

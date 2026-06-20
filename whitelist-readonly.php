<?php
require_once __DIR__ . '/blacklist_admin_auth.php';
error_reporting(E_ALL);
ini_set('display_errors', 1);
header('Content-Type: text/html; charset=utf-8');

// Eğer message tanımlı değilse, başlangıçta boş bir değer atayın
if (!isset($_SESSION['message'])) {
    $_SESSION['message'] = "";
}

// Dosya yolları
$whitelist_path = "/var/www/html/whitelist.txt";

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

// Whitelist Görüntüleme Fonksiyonu - Read-Only Sürüm
function display_whitelist($search_ip = '', $per_page = 10, $page = 1) {
    global $whitelist_path;
    
    // Whitelist içeriğini oku
    $whitelist_content = file_exists($whitelist_path) ? file($whitelist_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    
    // İçeriği işle (yorum satırlarını ayır ve IP'leri al)
    $whitelist_items = [];
    foreach ($whitelist_content as $line) {
        $line = trim($line);
        // Yorum satırı mı?
        if (substr($line, 0, 1) === '#') {
            $description = ltrim($line, '# ');
            $whitelist_items[] = ['ip' => '', 'description' => $description, 'is_comment' => true];
        } elseif (!empty($line)) {
            // IP veya subnet ise
            if (filter_var(explode('/', $line)[0], FILTER_VALIDATE_IP) || 
                (strpos($line, '/') !== false && validate_ip($line))) {
                $whitelist_items[] = ['ip' => $line, 'description' => '', 'is_comment' => false];
            }
        }
    }
    
    // Arama yapılıyorsa filtrele
    if (!empty($search_ip)) {
        $filtered_items = [];
        foreach ($whitelist_items as $item) {
            if ((!$item['is_comment'] && strpos($item['ip'], $search_ip) !== false) ||
                ($item['is_comment'] && strpos($item['description'], $search_ip) !== false)) {
                $filtered_items[] = $item;
            }
        }
        $whitelist_items = $filtered_items;
    }
    
    $total_items = count($whitelist_items);
    $total_pages = ceil($total_items / $per_page);
    if ($total_pages < 1) $total_pages = 1;
    $page = max(1, min($page, $total_pages));
    $start_index = ($page - 1) * $per_page;
    $displayed_items = array_slice($whitelist_items, $start_index, $per_page);
    
    // Arama çubuğu
    echo "<div class='search-bar'>";
    echo "<form method='get' action='" . htmlspecialchars($_SERVER["PHP_SELF"]) . "'>";
    echo "<table class='search-table' cellpadding='0' cellspacing='0'><tr>";
    echo "<td style='width:100%'><input type='text' name='search' class='form-control' placeholder='IP Adresi veya açıklama ara...' value='" . htmlspecialchars($search_ip) . "'></td>";
    echo "<td><button type='submit' class='btn btn-primary'><i class='fas fa-search'></i> Ara</button></td>";
    echo "</tr></table>";
    echo "<input type='hidden' name='per_page' value='" . $per_page . "'>";
    echo "</form>";
    echo "</div>";
    
    // Sayfa başına gösterim seçeneği
    echo "<div class='action-bar'>";
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
    echo "</form>";
    echo "</div>";
    echo "</div>"; // action-bar end
    
    // Tablo
    echo "<div class='table-responsive'>";
    echo "<table class='data-table'>";
    echo "<thead>";
    echo "<tr>
            <th>IP Adresi/Subnet</th>
            <th>Açıklama</th>
          </tr>";
    echo "</thead>";
    echo "<tbody>";
    
    if (count($displayed_items) == 0) {
        echo "<tr><td colspan='2' class='no-records'>Kayıt bulunamadı</td></tr>";
    } else {
        foreach ($displayed_items as $item) {
            if ($item['is_comment']) {
                echo "<tr class='comment-row'>";
                echo "<td colspan='2' class='comment'>" . htmlspecialchars($item['description']) . "</td>";
                echo "</tr>";
            } else {
                echo "<tr>";
                echo "<td>" . htmlspecialchars($item['ip']) . "</td>";
                echo "<td>" . htmlspecialchars($item['description']) . "</td>";
                echo "</tr>";
            }
        }
    }
    
    echo "</tbody>";
    echo "</table>";
    echo "</div>"; // table-responsive end
    
    echo "<div class='record-info'>Toplam: <b>$total_items</b> kayıt</div>";
    
    // Sayfalama
    if ($total_pages > 1) {
        echo "<div class='pagination'>";
        if ($page > 1) {
            echo "<a href='?page=" . ($page - 1) . "&per_page=$per_page&search=$search_ip' class='page-link'>&laquo; Önceki</a>";
        }
        
        // Sayfa numaralarını göster
        $max_pages_to_show = 5;
        $start_page = max(1, min($page - floor($max_pages_to_show / 2), $total_pages - $max_pages_to_show + 1));
        $end_page = min($start_page + $max_pages_to_show - 1, $total_pages);
        
        if ($start_page > 1) {
            echo "<a href='?page=1&per_page=$per_page&search=$search_ip' class='page-link'>1</a>";
            if ($start_page > 2) {
                echo "<span class='page-ellipsis'>...</span>";
            }
        }
        
        for ($i = $start_page; $i <= $end_page; $i++) {
            if ($i == $page) {
                echo "<span class='page-link current'>$i</span>";
            } else {
                echo "<a href='?page=$i&per_page=$per_page&search=$search_ip' class='page-link'>$i</a>";
            }
        }
        
        if ($end_page < $total_pages) {
            if ($end_page < $total_pages - 1) {
                echo "<span class='page-ellipsis'>...</span>";
            }
            echo "<a href='?page=$total_pages&per_page=$per_page&search=$search_ip' class='page-link'>$total_pages</a>";
        }
        
        if ($page < $total_pages) {
            echo "<a href='?page=" . ($page + 1) . "&per_page=$per_page&search=$search_ip' class='page-link'>Sonraki &raquo;</a>";
        }
        echo "</div>";
    }
}

// Kullanıcıdan arama terimini ve sayfa ayarlarını al
$search_ip = isset($_GET['search']) ? trim($_GET['search']) : '';
$per_page = isset($_GET['per_page']) ? (int)$_GET['per_page'] : 10;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyberwebeyeos Whitelist Görüntüleme Arayüzü</title>
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

        .readonly-badge {
            background-color: var(--warning-color);
            color: #333;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            margin-left: 10px;
            display: inline-block;
        }

        /* Main Layout */
        .container {
            max-width: 1600px;
            margin: 20px auto;
            padding: 0 15px;
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
            display: flex;
            align-items: center;
        }

        .card-body {
            padding: 20px;
        }

        /* Form Styles */
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

        /* Comment Row Style */
        .comment-row {
            background-color: #f5f5f5;
        }

        .comment {
            font-style: italic;
            color: #666;
        }

        /* Sütun genişlikleri */
        .data-table th:nth-child(1), .data-table td:nth-child(1) { width: 30%; }
        .data-table th:nth-child(2), .data-table td:nth-child(2) { width: 70%; }

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
            justify-content: flex-end;
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

        .per-page-section {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Search Bar */
        .search-bar {
            margin-bottom: 20px;
        }

        .search-table {
            width: 100%;
            border-collapse: collapse;
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
    </style>
</head>

<body>
    <header class="header">
        <div class="header-content">
            <h1 class="header-title">
                Cyberwebeyeos Whitelist Görüntüleme Arayüzü
                <span class="readonly-badge">Salt Okunur</span>
            </h1>
            <div class="header-actions">
                <a href="blacklist_readonly.php" class="btn btn-success">
                    <i class="fas fa-ban"></i> Kara Liste Görüntüle
                </a>
                <a href="whitelist.php" class="btn btn-primary">
                    <i class="fas fa-edit"></i> Yönetim Arayüzüne Git
                </a>
            </div>
            <img src="/images/cyberwebeyeos.png" alt="Cyberwebeyeos Logo" class="logo">
        </div>
    </header>

    <?php if (isset($_SESSION['message']) && !empty($_SESSION['message'])): ?>
    <div class="container">
        <div class="alert">
            <?php echo $_SESSION['message']; ?>
            <button type="button" class="close" onclick="this.parentElement.style.display='none'">&times;</button>
        </div>
    </div>
    <?php unset($_SESSION['message']); endif; ?>

    <div class="container">
        <!-- Beyaz Liste Tablosu -->
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">
                    <i class="fas fa-shield-alt"></i> Beyaz Liste (Whitelist)
                    <span class="readonly-badge">Salt Okunur</span>
                </h2>
            </div>
            <div class="card-body">
                <?php display_whitelist($search_ip, $per_page, $page); ?>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2024 Cyberwebeyeos. Tüm hakları saklıdır.</p>
    </footer>
</body>
</html>

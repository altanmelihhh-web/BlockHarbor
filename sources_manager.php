<?php
// Standalone auth (CWE_BLACKLIST_SESSION)
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';

// R26 (T1.1 RBAC): kaynak yönetimi yalnız admin (POST request'leri için)
// GET (görüntüleme) tüm authed kullanıcılara açık olabilir; ama dosya gönderdiği action'lar POST.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_role(['admin']);
}

error_reporting(E_ALL);
ini_set('display_errors', 1);
header('Content-Type: text/html; charset=utf-8');

$config_file = '/var/www/html/sources_config.json';

// Config dosyasını oku
function load_config() {
    global $config_file;
    if (!file_exists($config_file)) {
        return ['sources' => [], 'settings' => []];
    }
    $content = file_get_contents($config_file);
    return json_decode($content, true) ?: ['sources' => [], 'settings' => []];
}

// Config dosyasına yaz
function save_config($config) {
    global $config_file;
    file_put_contents($config_file, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

// Kaynak ekle
function add_source($data) {
    $config = load_config();

    // R35 (T2.5): default_confidence — kaynak güvenilirliği (0-100, default 60)
    $default_conf = isset($data['default_confidence']) && $data['default_confidence'] !== ''
        ? max(0, min(100, (int)$data['default_confidence']))
        : 60;

    $new_source = [
        'id' => uniqid('source_'),
        'name' => $data['name'],
        'url' => $data['url'],
        'type' => $data['type'],
        'update_interval' => (int)$data['update_interval'],
        'enabled' => isset($data['enabled']),
        'output_file' => '/var/www/html/' . preg_replace('/[^a-z0-9_-]/i', '_', strtolower($data['name'])) . '.txt',
        'description' => $data['description'],
        'default_confidence' => $default_conf,
        'last_update' => null,
        'entry_count' => 0,
        'last_status' => null
    ];

    $config['sources'][] = $new_source;
    save_config($config);
    return true;
}

// Kaynağı aktif/pasif yap
function toggle_source($source_id, $enabled) {
    $config = load_config();

    foreach ($config['sources'] as &$source) {
        if ($source['id'] === $source_id) {
            $source['enabled'] = $enabled;
            break;
        }
    }

    save_config($config);
    return true;
}

// Kaynağı güncelle
function update_source_now($source_id) {
    $config = load_config();

    foreach ($config['sources'] as &$source) {
        if ($source['id'] === $source_id) {
            $result = fetch_source_content($source);

            $source['last_update'] = date('Y-m-d H:i:s');
            $source['entry_count'] = $result['count'];
            $source['last_status'] = $result['success'] ? 'success' : 'failed';

            save_config($config);
            return $result;
        }
    }

    return ['success' => false, 'error' => 'Source not found'];
}

// Kaynak içeriğini çek
function fetch_source_content($source) {
    // SSL doğrulamasız ve UA'lı bir fetch — bazı feed'ler (abuse.ch vb.) default UA'yı reddediyor
    $ctx = stream_context_create([
        'http'  => ['user_agent' => 'BlacklistAdmin/1.0 (+portal)', 'timeout' => 30, 'follow_location' => 1],
        'https' => ['user_agent' => 'BlacklistAdmin/1.0 (+portal)', 'timeout' => 30, 'follow_location' => 1],
        'ssl'   => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    $content = @file_get_contents($source['url'], false, $ctx);

    if ($content === false) {
        return ['success' => false, 'count' => 0, 'error' => 'Failed to fetch URL'];
    }

    require_once __DIR__ . '/../_shared/feed_parser.inc.php';

    // Faz 2 — target_type tanımlıysa tip-bilinçli parse (hostfile/URL/IoC validator dahil)
    if (!empty($source['target_type'])) {
        $filtered = bl_parse_feed_typed($content, $source['target_type']);
    } else {
        // Eski davranış — IP odaklı: yorum + private IP filter
        $lines = explode("\n", $content);
        $filtered = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || substr($line, 0, 1) === '#') continue;
            if (preg_match('/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.|169\.254\.|224\.|240\.|255\.)/', $line)) continue;
            $filtered[] = $line;
        }
    }

    // SPRINT7-FIX (R66): parent dir oluştur + write return value check
    // Bug: file_put_contents parent dir yoksa fail eder, eski kod return check yapmıyordu
    // → "success: true, count: 452037" raporlanıyor ama dosya hiç yazılmamış oluyordu
    $output_dir = dirname($source['output_file']);
    if (!is_dir($output_dir)) {
        if (!@mkdir($output_dir, 0775, true) && !is_dir($output_dir)) {
            return ['success' => false, 'count' => 0, 'error' => "Cannot create output dir: $output_dir"];
        }
    }

    $payload = implode("\n", $filtered);
    $bytes = @file_put_contents($source['output_file'], $payload);
    if ($bytes === false) {
        return ['success' => false, 'count' => 0, 'error' => "file_put_contents failed for {$source['output_file']}"];
    }

    // Verify file actually exists with expected size (lock conflicts, partial writes, disk full)
    if (!file_exists($source['output_file']) || filesize($source['output_file']) !== strlen($payload)) {
        return ['success' => false, 'count' => 0, 'error' => 'Write verification failed (size mismatch or file missing)'];
    }

    // Faz 2 — target_type tanımlıysa combined.txt'i yenile
    require_once __DIR__ . '/../_shared/sync_hooks.inc.php';
    bl_post_sync_rebuild($source);

    // C2: Every successful feed fetch must rebuild the firewall feed
    require_once __DIR__ . '/lib_firewall_feed.php';
    rebuild_firewall_feed();

    return ['success' => true, 'count' => count($filtered), 'error' => null];
}

// Kaynağı düzenle
function edit_source($source_id, $data) {
    $config = load_config();

    foreach ($config['sources'] as &$source) {
        if ($source['id'] === $source_id) {
            $source['name'] = $data['name'];
            $source['url'] = $data['url'];
            $source['type'] = $data['type'];
            $source['update_interval'] = (int)$data['update_interval'];
            $source['description'] = $data['description'];
            $source['enabled'] = isset($data['enabled']);
            // R35 (T2.5): default_confidence
            if (isset($data['default_confidence']) && $data['default_confidence'] !== '') {
                $source['default_confidence'] = max(0, min(100, (int)$data['default_confidence']));
            }
            break;
        }
    }

    save_config($config);
    return true;
}

// Kaynağı sil
function delete_source($source_id) {
    $config = load_config();

    $config['sources'] = array_filter($config['sources'], function($source) use ($source_id) {
        if ($source['id'] === $source_id) {
            // Dosyayı da sil
            if (file_exists($source['output_file'])) {
                @unlink($source['output_file']);
            }
            return false;
        }
        return true;
    });

    // Array'i yeniden indexle
    $config['sources'] = array_values($config['sources']);

    save_config($config);
    return true;
}

// Tüm kaynakları güncelle
function update_all_sources() {
    $config = load_config();
    $results = [];

    foreach ($config['sources'] as &$source) {
        if ($source['enabled']) {
            $result = fetch_source_content($source);

            $source['last_update'] = date('Y-m-d H:i:s');
            $source['entry_count'] = $result['count'];
            $source['last_status'] = $result['success'] ? 'success' : 'failed';

            $results[] = $result;
        }
    }

    save_config($config);
    return $results;
}

// POST işlemleri
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Kaynak ekle
    if (isset($_POST['add_source'])) {
        add_source($_POST);
        $_SESSION['message'] = 'Kaynak başarıyla eklendi';
        $_redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'sources_manager.php'; header('Location: ' . $_redir); exit;
        exit();
    }

    // Kaynağı aktif/pasif yap
    if (isset($_POST['toggle_source'])) {
        $source_id = $_POST['source_id'];
        $enabled = $_POST['enabled'] === '1';
        toggle_source($source_id, $enabled);
        $_SESSION['message'] = 'Kaynak ' . ($enabled ? 'aktif edildi' : 'pasif edildi');
        $_redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'sources_manager.php'; header('Location: ' . $_redir); exit;
        exit();
    }

    // Kaynağı güncelle
    if (isset($_POST['update_source'])) {
        $source_id = $_POST['source_id'];
        $result = update_source_now($source_id);
        if ($result['success']) {
            $_SESSION['message'] = 'Kaynak güncellendi: ' . $result['count'] . ' kayıt çekildi';
        } else {
            $_SESSION['message'] = 'Güncelleme başarısız: ' . $result['error'];
        }
        $_redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'sources_manager.php'; header('Location: ' . $_redir); exit;
        exit();
    }

    // Kaynağı düzenle
    if (isset($_POST['edit_source'])) {
        $source_id = $_POST['source_id'];
        edit_source($source_id, $_POST);
        $_SESSION['message'] = 'Kaynak başarıyla güncellendi';
        $_redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'sources_manager.php'; header('Location: ' . $_redir); exit;
        exit();
    }

    // Kaynağı sil
    if (isset($_POST['delete_source'])) {
        $source_id = $_POST['source_id'];
        delete_source($source_id);
        $_SESSION['message'] = 'Kaynak silindi';
        $_redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'sources_manager.php'; header('Location: ' . $_redir); exit;
        exit();
    }

    // Tümünü güncelle
    if (isset($_POST['update_all'])) {
        $results = update_all_sources();
        $success_count = count(array_filter($results, fn($r) => $r['success']));
        $_SESSION['message'] = "$success_count kaynak güncellendi";
        $_redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'sources_manager.php'; header('Location: ' . $_redir); exit;
        exit();
    }
}

$config = load_config();
$sources = $config['sources'];
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kaynak Yönetimi - Cyberwebeyeos Blacklist</title>
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
            max-width: 1600px;
            margin: 0 auto;
        }

        .header-title {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .container {
            max-width: 1600px;
            margin: 20px auto;
            padding: 0 15px;
        }

        .container-flex {
            display: flex;
            gap: 20px;
        }

        .main-content {
            flex: 3;
            min-width: 0;
        }

        .sidebar {
            flex: 1;
            min-width: 300px;
            max-width: 400px;
        }

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
            transition: border-color 0.15s ease-in-out;
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
            padding: 8px 16px;
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
        }

        .btn-success {
            color: #fff;
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .btn-success:hover {
            background-color: #218838;
        }

        .btn-danger {
            color: #fff;
            background-color: var(--danger-color);
            border-color: var(--danger-color);
        }

        .btn-danger:hover {
            background-color: #c82333;
        }

        .btn-warning {
            color: #212529;
            background-color: var(--warning-color);
            border-color: var(--warning-color);
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }

        .btn-info {
            color: #fff;
            background-color: var(--info-color);
            border-color: var(--info-color);
        }

        .btn-info:hover {
            background-color: #138496;
        }

        .btn-block {
            display: block;
            width: 100%;
        }

        .table-responsive {
            overflow-x: auto;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th,
        .data-table td {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }

        .data-table thead th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: var(--secondary-color);
            border-bottom: 2px solid var(--border-color);
        }

        .data-table tbody tr:hover {
            background-color: rgba(0, 85, 136, 0.05);
        }

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

        .badge[style*="background: #95a5a6"] {
            color: #fff;
        }

        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
            position: relative;
        }

        .alert-info {
            color: #0c5460;
            background-color: #d1ecf1;
            border-color: #bee5eb;
        }

        .close {
            position: absolute;
            top: 15px;
            right: 15px;
            font-size: 1.25rem;
            font-weight: 700;
            line-height: 1;
            color: inherit;
            background: none;
            border: none;
            cursor: pointer;
            opacity: 0.5;
        }

        .close:hover {
            opacity: 1;
        }

        .text-center {
            text-align: center;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }

        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 30px;
            border-radius: 8px;
            width: 90%;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .footer {
            padding: 15px;
            text-align: center;
            background-color: var(--dark-color);
            color: white;
            margin-top: 30px;
            font-size: 0.9rem;
        }

        @media (max-width: 1200px) {
            .container-flex {
                flex-direction: column;
            }

            .main-content, .sidebar {
                width: 100%;
                max-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1 class="header-title">
                <i class="fas fa-cloud-download-alt"></i> Otomatik Kaynak Yönetimi
            </h1>
            <div style="display: flex; gap: 10px;">
                <form method="post" style="display:inline; margin: 0;">
                    <button type="submit" name="update_all" class="btn btn-success">
                        <i class="fas fa-sync"></i> Tüm Kaynakları Güncelle
                    </button>
                </form>
                <a href="cyberwebeyeosblacklistadmin.php" class="btn btn-primary">
                    <i class="fas fa-arrow-left"></i> Ana Sayfaya Dön
                </a>
            </div>
        </div>
    </div>

    <div class="container">
        <?php if (isset($_SESSION['message']) && !empty($_SESSION['message'])): ?>
            <div class="alert alert-info">
                <?php echo htmlspecialchars($_SESSION['message']); ?>
                <button class="close" onclick="this.parentElement.remove()">&times;</button>
            </div>
            <?php unset($_SESSION['message']); ?>
        <?php endif; ?>

        <div class="container-flex">
            <div class="main-content">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Yapılandırılmış Kaynaklar</h2>
                    </div>
                    <div class="card-body">
                        <?php if (empty($sources)): ?>
                            <p class="text-center" style="padding: 40px; color: #7f8c8d;">
                                Henüz kaynak yapılandırılmamış. Sağdaki formu kullanarak ilk kaynağınızı ekleyin.
                            </p>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Kaynak Adı</th>
                                            <th>URL</th>
                                            <th>Tip</th>
                                            <th>Süre (saat)</th>
                                            <th>Kayıt Sayısı</th>
                                            <th>Son Güncelleme</th>
                                            <th>Durum</th>
                                            <th>İşlemler</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($sources as $source): ?>
                                            <tr>
                                                <td><strong><?php echo htmlspecialchars($source['name']); ?></strong></td>
                                                <td style="font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                                    <a href="<?php echo htmlspecialchars($source['url']); ?>" target="_blank">
                                                        <?php echo htmlspecialchars($source['url']); ?>
                                                    </a>
                                                </td>
                                                <td><?php echo htmlspecialchars($source['type']); ?></td>
                                                <td><?php echo round($source['update_interval'] / 3600, 1); ?>h</td>
                                                <td><?php echo number_format($source['entry_count'] ?? 0); ?></td>
                                                <td style="font-size: 12px;">
                                                    <?php echo $source['last_update'] ?? 'Henüz güncellenmedi'; ?>
                                                </td>
                                                <td>
                                                    <?php if ($source['enabled']): ?>
                                                        <span class="badge badge-success">Aktif</span>
                                                    <?php else: ?>
                                                        <span class="badge" style="background: #95a5a6;">Pasif</span>
                                                    <?php endif; ?>
                                                    <?php if (isset($source['last_status']) && $source['last_status'] === 'success'): ?>
                                                        <span class="badge badge-success">✓</span>
                                                    <?php elseif (isset($source['last_status']) && $source['last_status'] === 'failed'): ?>
                                                        <span class="badge badge-danger">✗</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <button type="button" class="btn btn-sm btn-primary"
                                                            onclick="openEditModal('<?php echo $source['id']; ?>')" title="Düzenle">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <form method="post" style="display: inline;">
                                                        <input type="hidden" name="source_id" value="<?php echo $source['id']; ?>">
                                                        <button type="submit" name="update_source" class="btn btn-sm btn-info" title="Şimdi Güncelle">
                                                            <i class="fas fa-sync"></i>
                                                        </button>
                                                    </form>
                                                    <form method="post" style="display: inline;">
                                                        <input type="hidden" name="source_id" value="<?php echo $source['id']; ?>">
                                                        <input type="hidden" name="enabled" value="<?php echo $source['enabled'] ? '0' : '1'; ?>">
                                                        <button type="submit" name="toggle_source" class="btn btn-sm btn-warning" title="Aktif/Pasif">
                                                            <i class="fas fa-power-off"></i>
                                                        </button>
                                                    </form>
                                                    <form method="post" style="display: inline;">
                                                        <input type="hidden" name="source_id" value="<?php echo $source['id']; ?>">
                                                        <button type="submit" name="delete_source" class="btn btn-sm btn-danger"
                                                                onclick="return confirm('Bu kaynağı silmek istediğinizden emin misiniz?')" title="Sil">
                                                            <i class="fas fa-trash"></i>
                                                        </button>
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

                <?php /* 2026-05-14 Tavsiye Edilen Kaynaklar bölümü — ana tabloyu bozmaz */ ?>
                <?php @include __DIR__ . '/../_shared/recommended_sources.inc.php'; ?>

            </div>

            <div class="sidebar">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-plus"></i> Kaynak Ekle</h3>
                    </div>
                    <div class="card-body">
                        <form method="post">
                            <div class="form-group">
                                <label>Kaynak Adı *</label>
                                <input type="text" name="name" class="form-control" required
                                       placeholder="ör: Emerging Threats">
                            </div>

                            <div class="form-group">
                                <label>URL *</label>
                                <input type="url" name="url" class="form-control" required
                                       placeholder="https://example.com/blacklist.txt">
                            </div>

                            <div class="form-group">
                                <label>Tip *</label>
                                <select name="type" class="form-control" required>
                                    <option value="plain">Plain Text</option>
                                    <option value="ipset">IPSet Format</option>
                                    <option value="netset">Netset Format</option>
                                </select>
                            </div>

                            <div class="form-group">
                                <label>Güncelleme Aralığı (saniye)</label>
                                <select name="update_interval" class="form-control">
                                    <option value="3600">1 Saat</option>
                                    <option value="21600">6 Saat</option>
                                    <option value="43200">12 Saat</option>
                                    <option value="86400" selected>24 Saat</option>
                                    <option value="604800">7 Gün</option>
                                </select>
                            </div>

                            <div class="form-group">
                                <label>Açıklama</label>
                                <textarea name="description" class="form-control" rows="2"></textarea>
                            </div>

                            <div class="form-group">
                                <label>
                                    <input type="checkbox" name="enabled" checked>
                                    Bu kaynağı aktif et
                                </label>
                            </div>

                            <button type="submit" name="add_source" class="btn btn-primary btn-block">
                                <i class="fas fa-plus"></i> Kaynak Ekle
                            </button>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-info-circle"></i> Popüler Kaynaklar</h3>
                    </div>
                    <div class="card-body" style="font-size: 12px;">
                        <p><strong>FireHOL Level 1:</strong><br>
                        <code style="font-size: 10px;">https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset</code></p>

                        <p><strong>CI Badguys:</strong><br>
                        <code style="font-size: 10px;">https://cinsscore.com/list/ci-badguys.txt</code></p>

                        <p><strong>Emerging Threats:</strong><br>
                        <code style="font-size: 10px;">https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt</code></p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <h2 style="margin-bottom: 20px;">
                <i class="fas fa-edit"></i> Kaynağı Düzenle
            </h2>
            <form method="post" id="editForm">
                <input type="hidden" name="source_id" id="edit_source_id">

                <div class="form-group">
                    <label>Kaynak Adı *</label>
                    <input type="text" name="name" id="edit_name" class="form-control" required>
                </div>

                <div class="form-group">
                    <label>URL *</label>
                    <input type="url" name="url" id="edit_url" class="form-control" required>
                </div>

                <div class="form-group">
                    <label>Tip</label>
                    <select name="type" id="edit_type" class="form-control">
                        <option value="plain">Plain Text</option>
                        <option value="json">JSON</option>
                        <option value="csv">CSV</option>
                    </select>
                </div>

                <div class="form-group">
                    <label>Güncelleme Aralığı (saniye) *</label>
                    <input type="number" name="update_interval" id="edit_update_interval"
                           class="form-control" min="300" required>
                    <small style="color: #7f8c8d;">Örnek: 3600 = 1 saat, 86400 = 1 gün</small>
                </div>

                <div class="form-group">
                    <label>Açıklama</label>
                    <textarea name="description" id="edit_description" class="form-control" rows="2"></textarea>
                </div>

                <div class="form-group">
                    <label>
                        <input type="checkbox" name="enabled" id="edit_enabled">
                        Aktif
                    </label>
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-danger" onclick="closeEditModal()">
                        <i class="fas fa-times"></i> İptal
                    </button>
                    <button type="submit" name="edit_source" class="btn btn-success">
                        <i class="fas fa-save"></i> Kaydet
                    </button>
                </div>
            </form>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2024 cyberwebeyeos. Tüm hakları saklıdır.</p>
    </div>

    <script>
        // Portal SPA sayfayı shadow DOM içine inject ettiği için identifier'ları
        // global scope'a koymuyoruz — IIFE + window expose kullanıyoruz.
        (function () {
            var sources = <?php echo json_encode($sources); ?>;

            function setIfExists(id, prop, val) {
                var el = document.getElementById(id);
                if (el) el[prop] = val;
            }

            window.openEditModal = function (sourceId) {
                var source = sources.find(function (s) { return s.id === sourceId; });
                if (!source) return;
                setIfExists('edit_source_id',       'value',   source.id);
                setIfExists('edit_name',            'value',   source.name);
                setIfExists('edit_url',             'value',   source.url);
                setIfExists('edit_type',            'value',   source.type);
                setIfExists('edit_update_interval', 'value',   source.update_interval);
                setIfExists('edit_description',    'value',   source.description || '');
                setIfExists('edit_enabled',         'checked', !!source.enabled);
                var modal = document.getElementById('editModal');
                if (modal) modal.style.display = 'block';
            };

            window.closeEditModal = function () {
                var modal = document.getElementById('editModal');
                if (modal) modal.style.display = 'none';
            };

            // Modal dışına tıklayınca kapat (window.onclick yerine modal'a delegate)
            document.addEventListener('click', function (event) {
                var modal = document.getElementById('editModal');
                if (modal && event.target === modal) window.closeEditModal();
            });
        })();
    </script>
</body>
</html>

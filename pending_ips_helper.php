<?php
/**
 * Bekleyen (Pending) IP'leri yönetmek için helper fonksiyonlar
 */

define('PENDING_IPS_FILE', '/var/www/html/pending_ips.json');

/**
 * Bekleyen IP'ler dosyasını yükler
 */
function load_pending_ips() {
    if (!file_exists(PENDING_IPS_FILE)) {
        return ['pending_ips' => []];
    }

    $content = file_get_contents(PENDING_IPS_FILE);
    $data = json_decode($content, true);

    if ($data === null) {
        return ['pending_ips' => []];
    }

    return $data;
}

/**
 * Bekleyen IP'leri dosyaya kaydeder
 */
function save_pending_ips($data) {
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $result = file_put_contents(PENDING_IPS_FILE, $json);
    if ($result === false) {
        return false;
    }
    chmod(PENDING_IPS_FILE, 0644);
    return true;
}

/**
 * Yeni bir bekleyen IP ekler
 *
 * @param string $ip IP adresi
 * @param string $source Kaynak (manuel)
 * @return string Token
 */
function add_pending_ip($ip, $source) {
    $data = load_pending_ips();

    // Aynı IP zaten beklemede mi kontrol et
    foreach ($data['pending_ips'] as $pending) {
        if ($pending['ip'] === $ip && $pending['status'] === 'pending') {
            // Zaten beklemede, mevcut token'ı döndür
            return $pending['id'];
        }

        // IP daha önce rejected edilmişse, ekleme (bypass edilmiş demektir)
        if ($pending['ip'] === $ip && $pending['status'] === 'rejected') {
            // Rejected IP'yi eklemeyi engelle - zaten bypass edilmiş
            return false;
        }
    }

    // Yeni token oluştur
    $token = bin2hex(random_bytes(16));

    $pending_ip = [
        'id' => $token,
        'ip' => $ip,
        'source' => $source,
        'created_at' => date('Y-m-d H:i:s'),
        'status' => 'pending'
    ];

    $data['pending_ips'][] = $pending_ip;
    save_pending_ips($data);

    return $token;
}

/**
 * Token ile bekleyen IP'yi bulur
 *
 * @param string $token Token
 * @return array|null IP verisi veya null
 */
function get_pending_ip_by_token($token) {
    $data = load_pending_ips();

    foreach ($data['pending_ips'] as $pending) {
        if ($pending['id'] === $token) {
            return $pending;
        }
    }

    return null;
}

/**
 * Bekleyen IP'yi onaylar (blacklist'e ekler)
 *
 * @param string $token Token
 * @return bool Başarılı mı?
 */
function approve_pending_ip($token) {
    $data = load_pending_ips();
    $found = false;
    $ip_to_add = null;
    $source_to_add = null;

    foreach ($data['pending_ips'] as &$pending) {
        if ($pending['id'] === $token && $pending['status'] === 'pending') {
            $pending['status'] = 'approved';
            $pending['approved_at'] = date('Y-m-d H:i:s');
            $found = true;
            $ip_to_add = $pending['ip'];
            $source_to_add = $pending['source'];
            break;
        }
    }

    if ($found) {
        save_pending_ips($data);

        // IP'yi manuel blacklist'e ekle
        if ($ip_to_add && $source_to_add) {
            add_ip_to_manual_blacklist($ip_to_add, $source_to_add);
        }

        return true;
    }

    return false;
}

/**
 * Bekleyen IP'yi reddeder (bypass - blacklist'e eklenmez)
 *
 * @param string $token Token
 * @return bool Başarılı mı?
 */
function reject_pending_ip($token) {
    $data = load_pending_ips();
    $found = false;

    foreach ($data['pending_ips'] as &$pending) {
        if ($pending['id'] === $token && $pending['status'] === 'pending') {
            $pending['status'] = 'rejected';
            $pending['rejected_at'] = date('Y-m-d H:i:s');
            $found = true;
            break;
        }
    }

    if ($found) {
        save_pending_ips($data);
        return true;
    }

    return false;
}

/**
 * IP'yi manuel blacklist dosyasına ekler
 *
 * @param string $ip IP adresi
 * @param string $source Kaynak
 */
function add_ip_to_manual_blacklist($ip, $source) {
    $blacklist_file = '/var/www/html/blacklist.txt';
    $timestamp = date('Y-m-d H:i:s');

    // CIDR notation ekle
    if (strpos($ip, '/') === false) {
        $ip .= '/32';
    }

    $line = "$ip||$timestamp||Auto-approved from $source (whitelist conflict)\n";
    file_put_contents($blacklist_file, $line, FILE_APPEND);
}

/**
 * Bekleyen IP'lerin sayısını döndürür
 *
 * @return int Bekleyen IP sayısı
 */
function count_pending_ips() {
    $data = load_pending_ips();
    $count = 0;

    foreach ($data['pending_ips'] as $pending) {
        if ($pending['status'] === 'pending') {
            $count++;
        }
    }

    return $count;
}

/**
 * Tüm bekleyen IP'leri listeler
 *
 * @return array Bekleyen IP'ler
 */
function list_pending_ips() {
    $data = load_pending_ips();
    $pending_list = [];

    foreach ($data['pending_ips'] as $pending) {
        if ($pending['status'] === 'pending') {
            $pending_list[] = $pending;
        }
    }

    return $pending_list;
}

/**
 * Eski (7 günden fazla) pending IP'leri temizler
 */
function cleanup_old_pending_ips() {
    $data = load_pending_ips();
    $cutoff_date = strtotime('-7 days');
    $cleaned = false;

    foreach ($data['pending_ips'] as $key => $pending) {
        $created = strtotime($pending['created_at']);
        if ($created < $cutoff_date && $pending['status'] !== 'pending') {
            unset($data['pending_ips'][$key]);
            $cleaned = true;
        }
    }

    if ($cleaned) {
        // Diziyi yeniden indeksle
        $data['pending_ips'] = array_values($data['pending_ips']);
        save_pending_ips($data);
    }
}
?>

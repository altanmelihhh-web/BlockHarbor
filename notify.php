<?php
/**
 * Cyberwebeyeos Notifications — email + webhook dispatcher
 * Kullanım: send_notification('event_type', ['key'=>'value', ...])
 */
define('NOTIFY_CONFIG', __DIR__ . '/notifications.json');

function notify_load_config(): array {
    if (!file_exists(NOTIFY_CONFIG)) return [];
    return json_decode(@file_get_contents(NOTIFY_CONFIG), true) ?: [];
}

function notify_save_config(array $cfg): bool {
    return (bool)@file_put_contents(NOTIFY_CONFIG, json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

/**
 * Send notification for an event if enabled.
 * @param string $event e.g. 'blacklist_add', 'user_delete'
 * @param array $details event context
 * @return bool true if at least one channel succeeded
 */
function send_notification(string $event, array $details = []): bool {
    $cfg = notify_load_config();
    if (empty($cfg['events'][$event])) return false; // event disabled

    $ts = date('Y-m-d H:i:s');
    $user = $_SESSION['cwe_user'] ?? 'system';
    $body = "Event: {$event}\nTime: {$ts}\nUser: {$user}\nDetails: " . json_encode($details, JSON_UNESCAPED_UNICODE);

    $sent = false;

    // Email (R36 T3.1: SMTP varsa fsockopen route, yoksa mail() fallback)
    if (!empty($cfg['email']['enabled']) && !empty($cfg['email']['to'])) {
        $subject = ($cfg['email']['subject_prefix'] ?? '[CWE-TIP]') . ' ' . $event;
        if (!empty($cfg['smtp']['enabled']) && !empty($cfg['smtp']['host'])) {
            require_once __DIR__ . '/smtp_client.php';
            $smtp_err = null;
            $ok = cwe_smtp_send([
                'host'       => $cfg['smtp']['host'],
                'port'       => (int)($cfg['smtp']['port'] ?? 587),
                'encryption' => $cfg['smtp']['encryption'] ?? 'tls',
                'username'   => $cfg['smtp']['username'] ?? '',
                'password'   => $cfg['smtp']['password'] ?? '',
                'from'       => $cfg['email']['from'] ?? 'cwe@localhost',
                'from_name'  => $cfg['email']['from_name'] ?? 'Cyberwebeyeos TIP',
                'to'         => $cfg['email']['to'],
                'subject'    => $subject,
                'body'       => $body,
            ], $smtp_err);
            if ($ok) $sent = true;
            if (!$ok && function_exists('error_log')) error_log("CWE-SMTP: $smtp_err");
        } else {
            $headers = "From: " . ($cfg['email']['from'] ?? 'cwe@localhost') . "\r\nContent-Type: text/plain; charset=utf-8\r\n";
            $sent = @mail($cfg['email']['to'], $subject, $body, $headers) || $sent;
        }
    }

    // Webhook
    if (!empty($cfg['webhook']['enabled']) && !empty($cfg['webhook']['url'])) {
        $payload = json_encode(['event'=>$event, 'ts'=>$ts, 'user'=>$user, 'details'=>$details], JSON_UNESCAPED_UNICODE);
        $ch = curl_init($cfg['webhook']['url']);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], array_map(fn($k,$v) => "$k: $v", array_keys($cfg['webhook']['headers'] ?? []), array_values($cfg['webhook']['headers'] ?? []))),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code >= 200 && $code < 300) $sent = true;
    }

    return $sent;
}

// POST handler — settings update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && basename($_SERVER['SCRIPT_NAME']) === 'notify.php') {
    require_once __DIR__ . '/blacklist_admin_auth.php';
    require_once __DIR__ . '/audit_log.php';
    $cfg = notify_load_config();
    if (isset($_POST['save_settings'])) {
        $cfg['email']['enabled'] = !empty($_POST['email_enabled']);
        $cfg['email']['to']      = trim($_POST['email_to'] ?? '');
        $cfg['email']['from']    = trim($_POST['email_from'] ?? $cfg['email']['from']);
        $cfg['email']['from_name'] = trim($_POST['email_from_name'] ?? 'Cyberwebeyeos TIP');
        $cfg['email']['subject_prefix'] = trim($_POST['subject_prefix'] ?? '[CWE-TIP]');
        // R36 (T3.1): SMTP fields
        $cfg['smtp']['enabled']    = !empty($_POST['smtp_enabled']);
        $cfg['smtp']['host']       = trim($_POST['smtp_host'] ?? '');
        $cfg['smtp']['port']       = max(1, min(65535, (int)($_POST['smtp_port'] ?? 587)));
        $cfg['smtp']['encryption'] = in_array($_POST['smtp_encryption'] ?? 'tls', ['tls','ssl','none'], true) ? $_POST['smtp_encryption'] : 'tls';
        $cfg['smtp']['username']   = trim($_POST['smtp_username'] ?? '');
        // Password — sadece girilirse güncelle (mevcut göstermemek için "" geçirilir)
        if (!empty($_POST['smtp_password'])) {
            $cfg['smtp']['password'] = $_POST['smtp_password'];
        }
        // R37 (T3.2): syslog fields
        $cfg['syslog']['enabled']  = !empty($_POST['syslog_enabled']);
        $cfg['syslog']['facility'] = in_array($_POST['syslog_facility'] ?? 'local0', ['local0','local1','local2','local3','local4','local5','local6','local7','user','daemon'], true) ? $_POST['syslog_facility'] : 'local0';
        $cfg['syslog']['ident']    = trim($_POST['syslog_ident'] ?? 'cyberwebeyeos-tip');
        $cfg['webhook']['enabled'] = !empty($_POST['webhook_enabled']);
        $cfg['webhook']['url']     = trim($_POST['webhook_url'] ?? '');
        foreach (['blacklist_add','blacklist_delete','whitelist_add','user_create','user_delete','user_password_change','source_fetch_failed','csv_import','api_ingest'] as $e) {
            $cfg['events'][$e] = !empty($_POST['event_' . $e]);
        }
        notify_save_config($cfg);
        audit_log_event('notify_settings_update', []);
        $_SESSION['message'] = '✅ Bildirim ayarları kaydedildi';
    } elseif (isset($_POST['test_notification'])) {
        // Force-fire test event regardless of enabled flag
        $cfg['events']['_test'] = true;
        notify_save_config($cfg);
        $ok = send_notification('_test', ['msg' => 'Test bildirimi — manuel tetik']);
        $_SESSION['message'] = $ok ? '✅ Test bildirimi gönderildi' : '⚠️ Hiçbir kanal aktif değil veya başarısız';
        unset($cfg['events']['_test']);
        notify_save_config($cfg);
    }
    header('Location: cyberwebeyeosblacklistadmin.php#status');
    exit;
}

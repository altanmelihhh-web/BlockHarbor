<?php
/**
 * Cyberwebeyeos — Pure-PHP SMTP Client (R36 T3.1)
 *
 * Composer / PHPMailer kullanmadan minimal SMTP gönderim. fsockopen + STARTTLS + AUTH LOGIN.
 *
 * Kullanım:
 *   $ok = cwe_smtp_send([
 *     'host'       => 'smtp.example.com',
 *     'port'       => 587,
 *     'username'   => 'noreply@example.com',
 *     'password'   => 'secret',
 *     'encryption' => 'tls', // tls (STARTTLS) | ssl (SMTPS) | none
 *     'from'       => 'noreply@example.com',
 *     'from_name'  => 'Cyberwebeyeos TIP',
 *     'to'         => 'admin@example.com',
 *     'subject'    => '[CWE] alert',
 *     'body'       => 'plain text',
 *   ], $err);
 *
 * Return: bool. $err set olur (string) hata varsa.
 */

function cwe_smtp_send(array $opts, ?string &$error = null): bool {
    $host = $opts['host'] ?? '';
    $port = (int)($opts['port'] ?? 587);
    $enc  = strtolower($opts['encryption'] ?? 'tls');
    $user = $opts['username'] ?? '';
    $pass = $opts['password'] ?? '';
    $from = $opts['from'] ?? $user;
    $from_name = $opts['from_name'] ?? 'Cyberwebeyeos TIP';
    $to = $opts['to'] ?? '';
    $subject = $opts['subject'] ?? '';
    $body = $opts['body'] ?? '';
    $timeout = (int)($opts['timeout'] ?? 8);

    if (!$host || !$to) { $error = 'host ve to zorunlu'; return false; }

    $remote = ($enc === 'ssl' ? 'tls://' : '') . $host . ':' . $port;
    $sock = @stream_socket_client($remote, $eno, $estr, $timeout, STREAM_CLIENT_CONNECT);
    if (!$sock) { $error = "connect failed: $estr ($eno)"; return false; }

    stream_set_timeout($sock, $timeout);

    $readline = function() use ($sock) {
        $line = '';
        while (!feof($sock)) {
            $chunk = fgets($sock, 1024);
            if ($chunk === false) return false;
            $line .= $chunk;
            if (strlen($chunk) >= 4 && $chunk[3] === ' ') break;
        }
        return $line;
    };
    $write = function(string $cmd) use ($sock) {
        fwrite($sock, $cmd . "\r\n");
    };

    // Greeting
    $line = $readline();
    if (!$line || strpos($line, '220') !== 0) { fclose($sock); $error = "no banner: $line"; return false; }

    $domain = $opts['ehlo_domain'] ?? (gethostname() ?: 'cwe.local');
    $write("EHLO $domain"); $resp = $readline();
    if (strpos($resp, '250') !== 0) { fclose($sock); $error = "EHLO failed: $resp"; return false; }

    // STARTTLS
    if ($enc === 'tls') {
        $write('STARTTLS'); $resp = $readline();
        if (strpos($resp, '220') !== 0) { fclose($sock); $error = "STARTTLS rejected: $resp"; return false; }
        if (!@stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            fclose($sock); $error = 'STARTTLS handshake failed'; return false;
        }
        $write("EHLO $domain"); $resp = $readline();
        if (strpos($resp, '250') !== 0) { fclose($sock); $error = "EHLO post-TLS failed: $resp"; return false; }
    }

    // AUTH LOGIN
    if ($user !== '') {
        $write('AUTH LOGIN'); $resp = $readline();
        if (strpos($resp, '334') !== 0) { fclose($sock); $error = "AUTH LOGIN rejected: $resp"; return false; }
        $write(base64_encode($user)); $resp = $readline();
        if (strpos($resp, '334') !== 0) { fclose($sock); $error = "AUTH user rejected: $resp"; return false; }
        $write(base64_encode($pass)); $resp = $readline();
        if (strpos($resp, '235') !== 0) { fclose($sock); $error = "AUTH password rejected: $resp"; return false; }
    }

    // MAIL FROM
    $write("MAIL FROM:<$from>"); $resp = $readline();
    if (strpos($resp, '250') !== 0) { fclose($sock); $error = "MAIL FROM rejected: $resp"; return false; }

    // RCPT TO (single recipient for now — multiple to'lar comma-split)
    foreach (preg_split('/[,;\s]+/', $to) as $rcpt) {
        $rcpt = trim($rcpt);
        if ($rcpt === '') continue;
        $write("RCPT TO:<$rcpt>"); $resp = $readline();
        if (strpos($resp, '250') !== 0 && strpos($resp, '251') !== 0) {
            fclose($sock); $error = "RCPT rejected ($rcpt): $resp"; return false;
        }
    }

    // DATA
    $write('DATA'); $resp = $readline();
    if (strpos($resp, '354') !== 0) { fclose($sock); $error = "DATA rejected: $resp"; return false; }

    $headers = [
        "From: $from_name <$from>",
        "To: $to",
        "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=",
        "Date: " . date('r'),
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 8bit",
        "Message-ID: <" . uniqid('cwe-') . "@$domain>",
        "X-Mailer: cyberwebeyeos-tip/1.0",
    ];
    // Dot-stuff body
    $body_lines = preg_split('/\r?\n/', $body);
    foreach ($body_lines as &$bl) {
        if (isset($bl[0]) && $bl[0] === '.') $bl = '.' . $bl;
    }
    $payload = implode("\r\n", $headers) . "\r\n\r\n" . implode("\r\n", $body_lines) . "\r\n.\r\n";
    fwrite($sock, $payload);
    $resp = $readline();
    if (strpos($resp, '250') !== 0) { fclose($sock); $error = "DATA termination rejected: $resp"; return false; }

    // QUIT
    $write('QUIT'); @$readline();
    fclose($sock);

    $error = null;
    return true;
}

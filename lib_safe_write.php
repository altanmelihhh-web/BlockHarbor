<?php
// SPRINT7-T1: Atomic write helper — prevents R66-class phantom-success bugs
// Pattern: write to .tmp.PID, verify size, atomic rename.
// Returns ['ok'=>bool, 'bytes'=>int, 'error'=>string|null]

function safe_write_atomic(string $dest_path, string $content): array {
    $dir = dirname($dest_path);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return ['ok' => false, 'bytes' => 0,
                    'error' => "parent dir missing and mkdir failed: $dir"];
        }
    }

    $tmp = $dest_path . '.tmp.' . getmypid();
    $bytes = @file_put_contents($tmp, $content, LOCK_EX);

    // Step 1: write returned false or 0 for non-empty content
    if ($bytes === false || ($bytes === 0 && strlen($content) > 0)) {
        @unlink($tmp);
        return ['ok' => false, 'bytes' => 0,
                'error' => "file_put_contents failed on $tmp"];
    }

    // Step 2: verify file exists and size matches
    if (!file_exists($tmp) || filesize($tmp) !== $bytes) {
        @unlink($tmp);
        return ['ok' => false, 'bytes' => $bytes,
                'error' => "post-write size mismatch on $tmp"];
    }

    // Step 3: atomic rename
    if (!@rename($tmp, $dest_path)) {
        @unlink($tmp);
        return ['ok' => false, 'bytes' => $bytes,
                'error' => "rename failed: $tmp -> $dest_path"];
    }

    // Step 4: verify final destination
    if (!file_exists($dest_path)) {
        return ['ok' => false, 'bytes' => $bytes,
                'error' => "post-rename file missing: $dest_path"];
    }

    return ['ok' => true, 'bytes' => $bytes, 'error' => null];
}

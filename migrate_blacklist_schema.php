<?php
/**
 * Cyberwebeyeos — Blacklist Schema Migration (R28 T1.2)
 *
 * Mevcut blacklist.txt entry'lerini 10-field schema'sına yükseltir.
 *
 *   Eski 5-field: value|comment|date|fqdn|jira
 *   Eski 6-field: value|comment|date|fqdn|jira|tlp     (R27 sonrası)
 *   Yeni 10-fld:  value|comment|date|fqdn|jira|tlp|type|added_by|confidence|valid_until
 *
 * Migration kuralları:
 *   - tlp boşsa 'WHITE'
 *   - type cwe_detect_type() ile otomatik (legacy entries için)
 *   - added_by 'legacy'
 *   - confidence 50 (orta — legacy için ihtiyatlı)
 *   - valid_until 'permanent' (legacy entry'ler süresiz)
 *
 * Çalıştırma:
 *   php migrate_blacklist_schema.php           # apply
 *   php migrate_blacklist_schema.php --dry     # preview only
 *
 * Idempotent: zaten 10-field olan entry'ler korunur.
 */

require_once __DIR__ . '/ioc_helpers.php';

$DRY = in_array('--dry', $argv, true) || in_array('-n', $argv, true);
$FILE = __DIR__ . '/blacklist.txt';
$BACKUP = $FILE . '.bak-' . date('Ymd-His');

if (!file_exists($FILE)) {
    fwrite(STDERR, "blacklist.txt bulunamadı: $FILE\n");
    exit(1);
}

$lines = file($FILE, FILE_IGNORE_NEW_LINES);
$out = [];
$stats = ['total' => 0, 'already_v10' => 0, 'migrated' => 0, 'comment_skip' => 0, 'empty' => 0];

foreach ($lines as $line) {
    if ($line === '') { $stats['empty']++; $out[] = ''; continue; }
    if (ltrim($line)[0] === '#') { $stats['comment_skip']++; $out[] = $line; continue; }

    $stats['total']++;
    $parts = explode('|', $line);
    $field_count = count($parts);

    if ($field_count >= 10) {
        // Zaten yeni schema — parse + reformat (normalize)
        $stats['already_v10']++;
        $entry = cwe_parse_blacklist_entry($line);
        $out[] = cwe_format_blacklist_entry($entry);
    } else {
        // Migrate: parse fills defaults, format outputs 10-field
        $entry = cwe_parse_blacklist_entry($line);
        // legacy entries → added_by='legacy', confidence=50, valid_until='permanent'
        $entry['added_by']    = $entry['added_by']   === 'legacy' ? 'legacy' : $entry['added_by'];
        $entry['confidence']  = isset($parts[8]) && $parts[8] !== '' ? (int)$parts[8] : 50;
        $entry['valid_until'] = isset($parts[9]) && $parts[9] !== '' ? $parts[9] : 'permanent';
        $stats['migrated']++;
        $out[] = cwe_format_blacklist_entry($entry);
    }
}

echo "=== Migration özeti ===\n";
foreach ($stats as $k => $v) printf("  %-15s %d\n", $k, $v);
echo "\n";

if ($DRY) {
    echo "[DRY-RUN] Değişiklik uygulanmadı. İlk 5 değişen satır önizleme:\n";
    $shown = 0;
    foreach ($lines as $i => $orig) {
        if ($orig === '' || ltrim($orig)[0] === '#') continue;
        if ($orig !== $out[$i]) {
            echo "  - $orig\n";
            echo "  + {$out[$i]}\n";
            if (++$shown >= 5) break;
        }
    }
    echo "\nUygulamak için '--dry' bayrağı olmadan çalıştır.\n";
    exit(0);
}

// Backup + write
if (!copy($FILE, $BACKUP)) {
    fwrite(STDERR, "Backup oluşturulamadı: $BACKUP\n");
    exit(2);
}
echo "Backup: $BACKUP\n";

file_put_contents($FILE, implode("\n", $out) . "\n");
echo "Migration tamamlandı: $FILE\n";
echo "Geri almak için: cp $BACKUP $FILE\n";

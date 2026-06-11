<?php declare(strict_types=1);

namespace BlockHarbor\Audit;

use PDO;

/**
 * Recompute the audit_log hash chain end-to-end and report the first mismatch.
 *
 * For each row in id order we expect:
 *   row.prev_hash  == previous row's entry_hash   (or \x00 for the first row)
 *   row.entry_hash == sha256(prev_hash_bytes || canonical_json_utf8)
 * where canonical_json = json_encode({ts, actor, action, details})
 * — the same shape the BEFORE INSERT trigger produces in jsonb_build_object.
 */
final class ChainVerifier
{
    public function __construct(private readonly PDO $pdo) {}

    public function verify(?\DateTimeImmutable $since = null): VerifyResult
    {
        // Delegate canonical-json computation to PG: the trigger uses
        // jsonb_build_object(...)::text which has a PG-specific format
        // (whitespace, timestamptz rendering) that's painful to replicate
        // exactly in PHP. Instead, ask PG to recompute the entry_hash for
        // each row and compare against the stored value.
        $sql = <<<'SQL'
            SELECT id,
                   encode(prev_hash,  'hex') AS ph,
                   encode(entry_hash, 'hex') AS eh,
                   encode(
                     digest(
                       prev_hash || convert_to(
                         jsonb_build_object(
                           'ts',      ts,
                           'actor',   actor_username,
                           'action',  action,
                           'details', details
                         )::text,
                         'UTF8'
                       ),
                       'sha256'
                     ),
                     'hex'
                   ) AS computed_eh
            FROM audit_log
SQL;
        $params = [];
        if ($since !== null) {
            $sql .= ' WHERE ts >= :since';
            $params[':since'] = $since->format(\DateTimeInterface::ATOM);
        }
        $sql .= ' ORDER BY id';

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        $prevHashHex = '00'; // first row's prev_hash MUST be \x00
        $checked = 0;
        foreach ($stmt as $row) {
            $checked++;

            if ($row['ph'] !== $prevHashHex) {
                return new VerifyResult(
                    false,
                    $checked,
                    (int)$row['id'],
                    "prev_hash mismatch at id={$row['id']}: expected $prevHashHex, got {$row['ph']}",
                );
            }

            if ($row['eh'] !== $row['computed_eh']) {
                return new VerifyResult(
                    false,
                    $checked,
                    (int)$row['id'],
                    "entry_hash mismatch at id={$row['id']} — row content has been tampered with",
                );
            }

            $prevHashHex = $row['eh'];
        }

        return new VerifyResult(true, $checked, null, null);
    }
}

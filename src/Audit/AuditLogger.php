<?php declare(strict_types=1);

namespace BlockHarbor\Audit;

use PDO;

/**
 * Universal audit hook. Every domain service constructor should accept an
 * AuditLogger and call log() for state-changing operations.
 *
 * The audit_log table has a BEFORE INSERT trigger that computes prev_hash
 * and entry_hash — application code does not (and cannot, due to a planned
 * REVOKE in P7 hardening) supply them directly. We only provide:
 *   action, details, actor_username, actor_role, ip_address.
 */
final class AuditLogger
{
    public function __construct(private readonly PDO $pdo) {}

    /**
     * @param array<string,mixed> $details
     */
    public function log(
        string $action,
        array $details = [],
        ?string $actor = null,
        ?string $actorRole = null,
        ?string $ip = null,
    ): void {
        $stmt = $this->pdo->prepare(
            'INSERT INTO audit_log (action, actor_username, actor_role, ip_address, details)
             VALUES (:a, :u, :r, :ip, :d::jsonb)'
        );
        $stmt->execute([
            ':a'  => $action,
            ':u'  => $actor,
            ':r'  => $actorRole,
            ':ip' => $ip,
            ':d'  => json_encode($details, JSON_THROW_ON_ERROR),
        ]);
    }
}

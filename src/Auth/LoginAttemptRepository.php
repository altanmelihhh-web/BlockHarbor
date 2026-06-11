<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use PDO;

final class LoginAttemptRepository
{
    public function __construct(private readonly PDO $pdo) {}

    public function record(
        ?string $username,
        string $ip,
        bool $success,
        ?string $failureReason = null,
        ?string $userAgent = null,
    ): void {
        $stmt = $this->pdo->prepare(
            'INSERT INTO login_attempts (username, ip_address, success, failure_reason, user_agent)
             VALUES (:u, :ip, :s, :r, :ua)'
        );
        $stmt->execute([
            ':u'  => $username,
            ':ip' => $ip,
            ':s'  => $success ? 't' : 'f',
            ':r'  => $failureReason,
            ':ua' => $userAgent,
        ]);
    }

    public function countFailuresByIp(string $ip, int $windowSeconds): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT count(*) FROM login_attempts
             WHERE ip_address = :ip
               AND success = false
               AND created_at > now() - make_interval(secs => :s)'
        );
        $stmt->execute([':ip' => $ip, ':s' => $windowSeconds]);
        return (int)$stmt->fetchColumn();
    }

    public function countFailuresByUsername(string $username, int $windowSeconds): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT count(*) FROM login_attempts
             WHERE username = :u
               AND success = false
               AND created_at > now() - make_interval(secs => :s)'
        );
        $stmt->execute([':u' => $username, ':s' => $windowSeconds]);
        return (int)$stmt->fetchColumn();
    }
}

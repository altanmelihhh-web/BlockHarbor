<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use BlockHarbor\Core\Crypto;
use PDO;

final class UserTotpRepository
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly Crypto $crypto,
    ) {}

    /** @param list<string> $recoveryCodes plaintext codes (will be hashed) */
    public function enroll(int $userId, string $secret, array $recoveryCodes): void
    {
        $hashed = array_map(
            static fn(string $c): string => password_hash($c, PASSWORD_BCRYPT),
            $recoveryCodes,
        );
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_totp (user_id, secret_encrypted, recovery_codes_encrypted)
             VALUES (:u, :s, :c)
             ON CONFLICT (user_id) DO UPDATE SET
                secret_encrypted         = EXCLUDED.secret_encrypted,
                recovery_codes_encrypted = EXCLUDED.recovery_codes_encrypted,
                recovery_codes_used      = 0,
                verified_at              = NULL'
        );
        $stmt->execute([
            ':u' => $userId,
            ':s' => $this->crypto->encrypt($secret),
            ':c' => $this->crypto->encrypt(json_encode($hashed, JSON_THROW_ON_ERROR)),
        ]);
    }

    public function getSecret(int $userId): ?string
    {
        $stmt = $this->pdo->prepare('SELECT secret_encrypted FROM user_totp WHERE user_id = :u');
        $stmt->execute([':u' => $userId]);
        $cipher = $stmt->fetchColumn();
        return $cipher === false ? null : $this->crypto->decrypt((string)$cipher);
    }

    /** @return list<string> hashed (bcrypt) codes still valid */
    public function getRecoveryCodes(int $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT recovery_codes_encrypted FROM user_totp WHERE user_id = :u');
        $stmt->execute([':u' => $userId]);
        $cipher = $stmt->fetchColumn();
        if ($cipher === false) {
            return [];
        }
        /** @var list<string> $decoded */
        $decoded = json_decode($this->crypto->decrypt((string)$cipher), true) ?? [];
        return $decoded;
    }

    public function consumeRecoveryCode(int $userId, string $plainCode): bool
    {
        $hashed = $this->getRecoveryCodes($userId);
        foreach ($hashed as $i => $h) {
            if (password_verify($plainCode, $h)) {
                unset($hashed[$i]);
                $hashed = array_values($hashed);
                $stmt = $this->pdo->prepare(
                    'UPDATE user_totp
                     SET recovery_codes_encrypted = :c,
                         recovery_codes_used      = recovery_codes_used + 1
                     WHERE user_id = :u'
                );
                $stmt->execute([
                    ':c' => $this->crypto->encrypt(json_encode($hashed, JSON_THROW_ON_ERROR)),
                    ':u' => $userId,
                ]);
                return true;
            }
        }
        return false;
    }

    public function markVerified(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_totp SET verified_at = now() WHERE user_id = :u'
        );
        $stmt->execute([':u' => $userId]);
    }

    public function isVerified(int $userId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT verified_at IS NOT NULL FROM user_totp WHERE user_id = :u'
        );
        $stmt->execute([':u' => $userId]);
        return (bool)$stmt->fetchColumn();
    }
}

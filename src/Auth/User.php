<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use DateTimeImmutable;

final class User
{
    public function __construct(
        public readonly int $id,
        public readonly string $tenantId,
        public readonly string $username,
        public readonly ?string $email,
        public readonly ?string $passwordHash,
        public readonly string $role,
        public readonly bool $active,
        public readonly int $failedLoginCount,
        public readonly ?DateTimeImmutable $lockedUntil,
        public readonly ?DateTimeImmutable $lastLoginAt,
        public readonly ?DateTimeImmutable $passwordChangedAt,
        public readonly bool $mfaRequired,
        public readonly bool $mustChangePassword,
    ) {}

    /** @param array<string,mixed> $row */
    public static function fromRow(array $row): self
    {
        return new self(
            id: (int)$row['id'],
            tenantId: (string)$row['tenant_id'],
            username: (string)$row['username'],
            email: $row['email'] !== null ? (string)$row['email'] : null,
            passwordHash: $row['password_hash'] !== null ? (string)$row['password_hash'] : null,
            role: (string)$row['role'],
            active: (bool)$row['active'],
            failedLoginCount: (int)$row['failed_login_count'],
            lockedUntil: $row['locked_until'] ? new DateTimeImmutable((string)$row['locked_until']) : null,
            lastLoginAt: $row['last_login_at'] ? new DateTimeImmutable((string)$row['last_login_at']) : null,
            passwordChangedAt: $row['password_changed_at'] ? new DateTimeImmutable((string)$row['password_changed_at']) : null,
            mfaRequired: (bool)$row['mfa_required'],
            mustChangePassword: (bool)($row['must_change_password'] ?? false),
        );
    }

    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil > new DateTimeImmutable();
    }
}

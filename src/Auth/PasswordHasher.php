<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

final class PasswordHasher
{
    public function __construct(
        private readonly int $memoryCost = 65536,  // 64 MiB
        private readonly int $timeCost   = 3,
        private readonly int $threads    = 1,
    ) {}

    public function hash(string $plain): string
    {
        $hash = password_hash($plain, PASSWORD_ARGON2ID, $this->options());
        if ($hash === false) {
            throw new \RuntimeException('Failed to hash password');
        }
        return $hash;
    }

    public function verify(string $plain, string $hash): bool
    {
        if ($hash === '' || !str_starts_with($hash, '$argon2')) {
            return false;
        }
        return password_verify($plain, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, $this->options());
    }

    /** @return array{memory_cost:int,time_cost:int,threads:int} */
    private function options(): array
    {
        return [
            'memory_cost' => $this->memoryCost,
            'time_cost'   => $this->timeCost,
            'threads'     => $this->threads,
        ];
    }
}

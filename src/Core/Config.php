<?php declare(strict_types=1);

namespace BlockHarbor\Core;

final class Config
{
    /** @param array<string,string> $env */
    public function __construct(private readonly array $env) {}

    public static function fromEnvFile(string $path): self
    {
        $dotenv = \Dotenv\Dotenv::createImmutable(dirname($path), basename($path));
        $dotenv->safeLoad();
        /** @var array<string,string> $env */
        $env = $_ENV + $_SERVER + getenv();
        return new self($env);
    }

    public function string(string $key, ?string $default = null): string
    {
        $v = $this->env[$key] ?? null;
        if ($v === null || $v === '') {
            if ($default === null) {
                throw new \RuntimeException("Required env var missing: $key");
            }
            return $default;
        }
        return (string)$v;
    }

    public function int(string $key, ?int $default = null): int
    {
        $v = $this->env[$key] ?? null;
        if ($v === null || $v === '') {
            if ($default === null) {
                throw new \RuntimeException("Required env var missing: $key");
            }
            return $default;
        }
        return (int)$v;
    }

    public function bool(string $key, ?bool $default = null): bool
    {
        $v = $this->env[$key] ?? null;
        if ($v === null || $v === '') {
            if ($default === null) {
                throw new \RuntimeException("Required env var missing: $key");
            }
            return $default;
        }
        return in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }
}

<?php declare(strict_types=1);

namespace BlockHarbor\Core;

final class Csrf
{
    private const SESSION_KEY = '_csrf';

    public function token(): string
    {
        if (!isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }
        return $_SESSION[self::SESSION_KEY];
    }

    public function verify(?string $candidate): bool
    {
        $expected = $_SESSION[self::SESSION_KEY] ?? null;
        if ($expected === null || $candidate === null) {
            return false;
        }
        return hash_equals($expected, $candidate);
    }

    public function rotate(): void
    {
        unset($_SESSION[self::SESSION_KEY]);
    }
}

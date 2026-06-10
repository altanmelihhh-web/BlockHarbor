<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Unit\Core;

use BlockHarbor\Core\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function test_returns_string_value(): void
    {
        $cfg = new Config(['APP_ENV' => 'production']);
        self::assertSame('production', $cfg->string('APP_ENV'));
    }

    public function test_returns_int_value(): void
    {
        $cfg = new Config(['SESSION_LIFETIME' => '1800']);
        self::assertSame(1800, $cfg->int('SESSION_LIFETIME'));
    }

    public function test_returns_bool_value(): void
    {
        $cfg = new Config(['APP_DEBUG' => 'true']);
        self::assertTrue($cfg->bool('APP_DEBUG'));

        $cfg2 = new Config(['APP_DEBUG' => 'false']);
        self::assertFalse($cfg2->bool('APP_DEBUG'));
    }

    public function test_returns_default_when_missing(): void
    {
        $cfg = new Config([]);
        self::assertSame('fallback', $cfg->string('MISSING', 'fallback'));
        self::assertSame(42, $cfg->int('MISSING', 42));
        self::assertFalse($cfg->bool('MISSING', false));
    }

    public function test_throws_when_required_missing(): void
    {
        $cfg = new Config([]);
        $this->expectException(\RuntimeException::class);
        $cfg->string('REQUIRED');
    }
}

<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Unit\Auth;

use BlockHarbor\Auth\TotpService;
use PHPUnit\Framework\TestCase;

final class TotpServiceTest extends TestCase
{
    public function test_generate_secret_returns_base32(): void
    {
        $svc = new TotpService();
        $secret = $svc->generateSecret();
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
        self::assertGreaterThanOrEqual(26, strlen($secret));
    }

    public function test_verify_accepts_current_otp(): void
    {
        $svc = new TotpService();
        $secret = $svc->generateSecret();
        self::assertTrue($svc->verify($secret, $svc->currentCode($secret)));
    }

    public function test_verify_rejects_wrong_code(): void
    {
        $svc = new TotpService();
        self::assertFalse($svc->verify($svc->generateSecret(), '000000'));
    }

    public function test_provisioning_uri_includes_issuer_and_label(): void
    {
        $svc = new TotpService(issuer: 'BlockHarbor');
        $uri = $svc->provisioningUri($svc->generateSecret(), 'alice@example.com');
        self::assertStringStartsWith('otpauth://totp/', $uri);
        self::assertStringContainsString('BlockHarbor', $uri);
        self::assertStringContainsString('alice', $uri);
    }

    public function test_generate_recovery_codes_returns_10_unique(): void
    {
        $svc = new TotpService();
        $codes = $svc->generateRecoveryCodes();
        self::assertCount(10, $codes);
        self::assertCount(10, array_unique($codes));
        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $code);
        }
    }
}

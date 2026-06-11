<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use OTPHP\TOTP;

final class TotpService
{
    public function __construct(
        private readonly string $issuer = 'BlockHarbor',
        private readonly int $digits = 6,
        private readonly int $period = 30,
    ) {}

    public function generateSecret(): string
    {
        return TOTP::generate()->getSecret();
    }

    public function currentCode(string $secret): string
    {
        return $this->totp($secret)->now();
    }

    public function verify(string $secret, string $code): bool
    {
        // ±10s clock drift allowance (must be < period per otphp constraint).
        return $this->totp($secret)->verify($code, leeway: 10);
    }

    public function provisioningUri(string $secret, string $label): string
    {
        $totp = $this->totp($secret);
        $totp->setLabel($label);
        $totp->setIssuer($this->issuer);
        return $totp->getProvisioningUri();
    }

    /** @return list<string> 10 one-time codes in XXXX-XXXX format */
    public function generateRecoveryCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $codes[] = $this->randomGroup() . '-' . $this->randomGroup();
        }
        return $codes;
    }

    private function totp(string $secret): TOTP
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setDigits($this->digits);
        $totp->setPeriod($this->period);
        return $totp;
    }

    private function randomGroup(): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $out = '';
        for ($i = 0; $i < 4; $i++) {
            $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return $out;
    }
}

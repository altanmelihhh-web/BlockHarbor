<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Unit\Auth;

use BlockHarbor\Auth\PasswordPolicy;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyTest extends TestCase
{
    public function test_accepts_compliant_password(): void
    {
        $p = new PasswordPolicy(minLength: 12, requireMixedCase: true, requireDigit: true, requireSpecial: true);
        self::assertSame([], $p->validate('Str0ng!Pass#word'));
    }

    public function test_rejects_short_password(): void
    {
        $p = new PasswordPolicy(minLength: 12);
        self::assertContains('too_short', $p->validate('Ab1!'));
    }

    public function test_rejects_when_missing_mixed_case(): void
    {
        $p = new PasswordPolicy(minLength: 8, requireMixedCase: true);
        self::assertContains('missing_mixed_case', $p->validate('alllowercase1!'));
        self::assertContains('missing_mixed_case', $p->validate('ALLUPPERCASE1!'));
    }

    public function test_rejects_when_missing_digit(): void
    {
        $p = new PasswordPolicy(minLength: 8, requireDigit: true);
        self::assertContains('missing_digit', $p->validate('NoDigits!Here'));
    }

    public function test_rejects_when_missing_special(): void
    {
        $p = new PasswordPolicy(minLength: 8, requireSpecial: true);
        self::assertContains('missing_special', $p->validate('NoSpecial1Here'));
    }

    public function test_returns_multiple_failures(): void
    {
        $p = new PasswordPolicy(minLength: 12, requireMixedCase: true, requireDigit: true, requireSpecial: true);
        $errors = $p->validate('short');
        self::assertContains('too_short',          $errors);
        self::assertContains('missing_mixed_case', $errors);
        self::assertContains('missing_digit',      $errors);
        self::assertContains('missing_special',    $errors);
    }
}

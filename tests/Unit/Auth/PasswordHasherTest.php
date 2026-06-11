<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Unit\Auth;

use BlockHarbor\Auth\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function test_hash_uses_argon2id(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct-horse-battery-staple');
        self::assertStringStartsWith('$argon2id$', $hash);
    }

    public function test_verify_correct_password(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('s3cret!password');
        self::assertTrue($hasher->verify('s3cret!password', $hash));
    }

    public function test_verify_wrong_password(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('s3cret!password');
        self::assertFalse($hasher->verify('wrong', $hash));
    }

    public function test_verify_empty_or_invalid_hash(): void
    {
        $hasher = new PasswordHasher();
        self::assertFalse($hasher->verify('anything', ''));
        self::assertFalse($hasher->verify('anything', 'not-a-hash'));
    }

    public function test_needs_rehash_when_parameters_change(): void
    {
        $weak     = new PasswordHasher(memoryCost: 1024, timeCost: 1);
        $oldHash  = $weak->hash('p');

        $stronger = new PasswordHasher(memoryCost: 65536, timeCost: 3);
        self::assertTrue($stronger->needsRehash($oldHash));
        self::assertFalse($stronger->needsRehash($stronger->hash('p')));
    }
}

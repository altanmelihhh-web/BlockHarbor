<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Core;

use BlockHarbor\Core\Crypto;
use BlockHarbor\Tests\DatabaseTestCase;

final class CryptoTest extends DatabaseTestCase
{
    public function test_encrypt_then_decrypt_roundtrip(): void
    {
        $crypto = new Crypto($this->db->pdo(), 'master-key-for-tests-only');
        $plain  = 'my-totp-secret-NBSWY3DPO5XXE3DE';
        $cipher = $crypto->encrypt($plain);

        self::assertNotSame($plain, $cipher);
        self::assertNotSame('', $cipher);
        self::assertSame($plain, $crypto->decrypt($cipher));
    }

    public function test_different_ciphertexts_for_same_plaintext(): void
    {
        $crypto = new Crypto($this->db->pdo(), 'master-key');
        $a = $crypto->encrypt('hello');
        $b = $crypto->encrypt('hello');
        // pgp_sym_encrypt uses random IV — same plaintext, different cipher
        self::assertNotSame($a, $b);
    }

    public function test_wrong_key_throws(): void
    {
        $cryptoA = new Crypto($this->db->pdo(), 'key-a');
        $cipher  = $cryptoA->encrypt('secret');

        $cryptoB = new Crypto($this->db->pdo(), 'key-b');
        $this->expectException(\RuntimeException::class);
        $cryptoB->decrypt($cipher);
    }
}

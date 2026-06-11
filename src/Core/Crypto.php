<?php declare(strict_types=1);

namespace BlockHarbor\Core;

use PDO;

/**
 * pgcrypto wrapper for symmetric encryption of small secrets
 * (TOTP secrets, recovery codes, API keys). Uses pgp_sym_encrypt which
 * includes a random IV per call — different ciphertexts for same plaintext.
 *
 * The master key is read from APP_KEY env var (32-byte hex) by the caller.
 * Rotating the key requires re-encrypting all stored secrets — handled
 * by a P7 ops script.
 */
final class Crypto
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $masterKey,
    ) {}

    public function encrypt(string $plain): string
    {
        $stmt = $this->pdo->prepare(
            "SELECT encode(pgp_sym_encrypt(:p, :k), 'base64') AS c"
        );
        $stmt->execute([':p' => $plain, ':k' => $this->masterKey]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            throw new \RuntimeException('pgp_sym_encrypt returned no row');
        }
        return (string)$row['c'];
    }

    public function decrypt(string $cipher): string
    {
        $stmt = $this->pdo->prepare(
            "SELECT pgp_sym_decrypt(decode(:c, 'base64'), :k) AS p"
        );
        try {
            $stmt->execute([':c' => $cipher, ':k' => $this->masterKey]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (\PDOException $e) {
            throw new \RuntimeException(
                'Decryption failed (wrong key or corrupt cipher)',
                0,
                $e,
            );
        }
        if (!$row || $row['p'] === null) {
            throw new \RuntimeException(
                'pgp_sym_decrypt returned NULL — bad key or corrupt cipher'
            );
        }
        return (string)$row['p'];
    }
}

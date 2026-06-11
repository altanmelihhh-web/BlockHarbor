<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Audit;

use BlockHarbor\Audit\AuditLogger;
use BlockHarbor\Audit\ChainVerifier;
use BlockHarbor\Tests\DatabaseTestCase;

final class ChainVerifierIntegrationTest extends DatabaseTestCase
{
    public function test_verifier_passes_on_clean_chain(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        for ($i = 0; $i < 5; $i++) {
            $logger->log("test.step.$i", ['n' => $i]);
        }

        $v = new ChainVerifier($this->db->pdo());
        $result = $v->verify();

        self::assertTrue($result->ok, "verify() failed: {$result->mismatchReason}");
        self::assertSame(5, $result->checked);
        self::assertNull($result->mismatchAtId);
    }

    public function test_verifier_detects_tampering_of_action(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        $logger->log('first',  []);
        $logger->log('second', []);
        $logger->log('third',  []);

        // Simulate tamper: mutate the action of the middle row in-place.
        // (In production audit_log is REVOKE'd in P7 hardening — this test
        //  uses the migrator role which currently has the access by design.)
        $this->db->pdo()->exec(
            "UPDATE audit_log SET action='TAMPERED'
             WHERE id=(SELECT id FROM audit_log ORDER BY id LIMIT 1 OFFSET 1)"
        );

        $v = new ChainVerifier($this->db->pdo());
        $result = $v->verify();

        self::assertFalse($result->ok);
        self::assertNotNull($result->mismatchAtId);
    }

    public function test_verifier_passes_on_empty_chain(): void
    {
        $v = new ChainVerifier($this->db->pdo());
        $result = $v->verify();

        self::assertTrue($result->ok);
        self::assertSame(0, $result->checked);
    }
}

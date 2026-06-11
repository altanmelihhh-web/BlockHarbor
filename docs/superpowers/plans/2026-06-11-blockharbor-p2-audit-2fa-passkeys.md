# BlockHarbor P2 — Audit + 2FA + Passkeys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Inline execution (controller-only) is acceptable for 1–2 file leaf tasks** per session feedback `[[feedback-subagent-overhead]]`.

**Goal:** Add universal audit logging + tamper-detection CLI + TOTP 2FA + WebAuthn/Passkeys + rule-based RiskScorer + step-up authentication to BlockHarbor. End state: an admin user logs in with password, is prompted for TOTP or passkey on every session, and risky logins (new IP / country / user-agent family) trigger step-up even for non-admin roles.

**Architecture:** Compose-only additions to the existing P1 flow. `AuditLogger` is injected into every domain service constructor (`UserRepository`, `AuthService`, future P3+ services) — the universal logging hook graphify identified as the highest-betweenness node in the legacy system. TOTP via `spomky-labs/otphp` (RFC 6238). WebAuthn via `web-auth/webauthn-lib` (canonical PHP impl). Secrets at rest via pgcrypto `pgp_sym_encrypt`. Risk scoring is rule-based (no ML) — auditable + deterministic + cheap to evaluate.

**Tech Stack:** PHP 8.1, PostgreSQL 14, Phinx, Plates, Tailwind, Alpine,  + new: `spomky-labs/otphp:^11.2`, `bacon/bacon-qr-code:^3.0`, `web-auth/webauthn-lib:^4.7`, `geoip2/geoip2:^3.0` (MaxMind GeoLite2 reader).

**Reference spec:** `docs/superpowers/specs/2026-06-07-blockharbor-db-migration-design.md` (§4.3.1 identity tables; §5 auth architecture; §6 audit log).

---

## P2 Scope: in vs out

### In scope

- `BlockHarbor\Audit\AuditLogger` class — wired into every existing service
  constructor; emits hash-chained rows into `audit_log` table (which already
  exists from P1 Task 8). Universal injection target.
- `BlockHarbor\Audit\ChainVerifier` — recomputes the chain end-to-end and
  reports the first mismatch.
- `bin/verify-audit-chain` — CLI wrapper for periodic monitoring
  (cron-scheduled by `bin/install.sh` Step 9 cron registry).
- 4 new migrations: `user_totp`, `user_passkeys`, `user_ip_allowlist`,
  `risk_events`.
- `BlockHarbor\Auth\TotpService` — secret generation, QR provisioning URI,
  code verification (with a 1-step grace window for clock drift), recovery
  codes (one-time use, hashed at rest).
- `BlockHarbor\Auth\WebAuthnService` — registration ceremony (server-side
  challenge → browser navigator.credentials.create → verifyRegistration →
  INSERT credential), assertion ceremony (challenge → get → verifyAssertion
  → session).
- `BlockHarbor\Auth\RiskScorer` — rule-based scoring (new IP +30, new
  country +40, new UA family +20, atypical hour +10). Total > 60 → step-up.
- `AuthService` enhancements:
  - After password success, decide if step-up required
  - New states: `RequiresMfa`, `RequiresMfaSetup`
  - Existing `Success` only fires after MFA OR if user doesn't need MFA
- New views: `auth/2fa-totp.php`, `auth/2fa-passkey.php`,
  `auth/2fa-setup.php`, `auth/2fa-recovery.php`.
- New controllers: `TwoFactorController`, `PasskeyController`,
  `TwoFactorSetupController`.
- Mid-login session state machine: after password OK but before MFA OK,
  `$_SESSION['pending_user_id']` holds the user (NOT `$_SESSION['user_id']`
  — that only lands after MFA).

### Out of scope (later plans)

- IOC domain (P3)
- Feed fetchers (P4)
- REST API keys + rate limiting (P5)
- JSON → DB import (P6)
- WebAuthn-only login (passwordless default) — listed as post-P7

### Working software at end of P2

```bash
# After P1 you could log in with password alone. After P2:
1. POST /login → password OK → redirect to /2fa
2. /2fa shows "Enter TOTP code or use passkey" (depending on what user has enrolled)
3. Submit valid code → session activated, redirect to /dashboard
4. New IP/country → step-up forced even if mfa_required=false in DB

# Verify audit:
./bin/verify-audit-chain
# → "Chain OK — 1,247 entries, all hashes match. Last entry: 2026-06-XX"
```

---

## File Structure

### Files created by P2

```text
/var/www/blockharbor/
├── composer.json                    # ADD otphp, bacon-qr-code, webauthn-lib, geoip2
├── src/
│   ├── Audit/
│   │   ├── AuditLogger.php          # NEW — universal hook
│   │   ├── AuditRepository.php      # NEW — read-side queries
│   │   └── ChainVerifier.php        # NEW — tamper detection
│   ├── Auth/
│   │   ├── TotpService.php          # NEW — RFC 6238 + recovery codes
│   │   ├── WebAuthnService.php      # NEW — FIDO2 ceremonies
│   │   ├── RiskScorer.php           # NEW — rule-based scoring
│   │   ├── MfaState.php             # NEW — enum: NotRequired|TotpRequired|PasskeyRequired|EitherRequired
│   │   ├── RecoveryCodeHasher.php   # NEW — bcrypt for one-time codes
│   │   ├── UserTotpRepository.php   # NEW
│   │   ├── UserPasskeyRepository.php# NEW
│   │   ├── RiskEventRepository.php  # NEW
│   │   ├── AuthResult.php           # MODIFY — add RequiresMfa, RequiresMfaSetup
│   │   ├── AuthService.php          # MODIFY — emit audit + check MFA
│   │   ├── Controllers/
│   │   │   ├── LoginController.php  # MODIFY — pending_user_id flow
│   │   │   ├── TwoFactorController.php       # NEW
│   │   │   ├── TwoFactorSetupController.php  # NEW
│   │   │   └── PasskeyController.php         # NEW
│   ├── Core/
│   │   └── Crypto.php               # NEW — pgcrypto wrapper for secret enc/dec
├── resources/views/auth/
│   ├── 2fa-totp.php                 # NEW
│   ├── 2fa-passkey.php              # NEW
│   ├── 2fa-setup.php                # NEW (QR + verification)
│   └── 2fa-recovery.php             # NEW (show recovery codes once)
├── db/migrations/
│   ├── 20260611120000_create_user_totp.php          # NEW
│   ├── 20260611120100_create_user_passkeys.php      # NEW
│   ├── 20260611120200_create_user_ip_allowlist.php  # NEW
│   └── 20260611120300_create_risk_events.php        # NEW
├── tests/
│   ├── Unit/Audit/
│   │   └── ChainVerifierTest.php
│   ├── Unit/Auth/
│   │   ├── TotpServiceTest.php
│   │   └── RiskScorerTest.php
│   ├── Integration/
│   │   ├── Audit/
│   │   │   ├── AuditLoggerTest.php
│   │   │   └── ChainVerifierIntegrationTest.php
│   │   └── Auth/
│   │       ├── UserTotpRepositoryTest.php
│   │       └── AuthServiceMfaTest.php
├── bin/
│   ├── verify-audit-chain           # NEW
│   └── cleanup-mfa-tokens           # NEW (cron target)
└── docs/
    └── security.md                   # NEW — threat model + MFA reset SOP
```

### File responsibilities

| File | Responsibility |
|---|---|
| `Audit/AuditLogger.php` | One method `log(string action, array details, ?string actor, ?string ip)`; inserts into `audit_log` (trigger handles chain) |
| `Audit/AuditRepository.php` | Read-side: timeline by actor / action / time range / id-pagination |
| `Audit/ChainVerifier.php` | Walks rows in order, recomputes `sha256(prev_hash \|\| canonical_json)`, returns `(ok: bool, mismatch_at_id: ?int)` |
| `Auth/TotpService.php` | `generateSecret() → string`, `provisioningUri(secret, user)`, `verify(secret, code) → bool`, `generateRecoveryCodes() → array<string>` |
| `Auth/WebAuthnService.php` | Wraps `web-auth/webauthn-lib`; emits + verifies attestation/assertion via session-bound challenges |
| `Auth/RiskScorer.php` | `evaluate(User, ip, ua) → int 0–100`. Pure rule application against `login_attempts` history + GeoIP2 + simple UA family parse. |
| `Auth/MfaState.php` | enum: `NotRequired \| TotpRequired \| PasskeyRequired \| EitherRequired` |
| `Auth/RecoveryCodeHasher.php` | bcrypt(code) at rest; `verify` is `password_verify` semantics |
| `Auth/UserTotpRepository.php` | CRUD on `user_totp` (encrypted via Crypto) |
| `Auth/UserPasskeyRepository.php` | CRUD on `user_passkeys` |
| `Auth/RiskEventRepository.php` | Insert + last-N queries |
| `Core/Crypto.php` | `encrypt(plaintext) → bytea` / `decrypt(bytea) → plaintext` via pgcrypto `pgp_sym_encrypt`; master key from `APP_KEY` env var |
| `Auth/Controllers/TwoFactorController.php` | GET shows TOTP form, POST verifies; on success activates session |
| `Auth/Controllers/TwoFactorSetupController.php` | First-time enrollment: generate secret, show QR + recovery codes, verify confirmation code |
| `Auth/Controllers/PasskeyController.php` | Registration + assertion ceremonies |

---

## Conventions

- All steps assume CWD `/var/www/blockharbor/` and PHP 8.1.2 host.
- `composer test` invoked with `COMPOSER_ALLOW_SUPERUSER=1` per session pattern.
- PSR-4 namespace root remains `BlockHarbor\` → `src/`.
- Every new domain table gets `tenant_id` column with `'00000000-…'` default (multi-tenant prep, P5/RLS).
- TDD per task: failing test → minimal code → passing test → commit.
- Static analysis: PHPStan level 8 must remain clean on `src/`.

---

## Task 1: Composer Dependencies

**Files:**
- Modify: `composer.json`

- [ ] **Step 1: Add new require entries**

Edit `composer.json` and merge into the `require` block:

```json
{
  "require": {
    ...
    "spomky-labs/otphp": "^11.2",
    "bacon/bacon-qr-code": "^3.0",
    "web-auth/webauthn-lib": "^4.7",
    "geoip2/geoip2": "^3.0"
  }
}
```

- [ ] **Step 2: composer update**

Run:
```bash
cd /var/www/blockharbor
COMPOSER_ALLOW_SUPERUSER=1 composer update spomky-labs/otphp bacon/bacon-qr-code web-auth/webauthn-lib geoip2/geoip2 --with-all-dependencies
```

Expected: all four resolve. Note any subsumed transitive deps (e.g. `paragonie/constant_time_encoding`).

- [ ] **Step 3: Sanity import test**

Quick PHP sanity check:
```bash
php -r 'require "vendor/autoload.php"; echo OTPHP\TOTP::generate()->getSecret(), "\n";'
```

Expected: a base32 secret string ≈ 32 chars.

- [ ] **Step 4: Commit**

```bash
git add composer.json composer.lock
git commit -m "chore: add P2 dependencies (TOTP, QR, WebAuthn, GeoIP2)

- spomky-labs/otphp ^11.2 — RFC 6238 TOTP impl
- bacon/bacon-qr-code ^3.0 — QR rendering for TOTP provisioning URI
- web-auth/webauthn-lib ^4.7 — FIDO2 ceremonies
- geoip2/geoip2 ^3.0 — MaxMind GeoLite2 reader for RiskScorer"
git push origin main
```

---

## Task 2: Core Crypto wrapper (pgcrypto)

**Files:**
- Create: `src/Core/Crypto.php`
- Create: `tests/Integration/Core/CryptoTest.php`

- [ ] **Step 1: Write failing test**

Create `tests/Integration/Core/CryptoTest.php`:
```php
<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Core;

use BlockHarbor\Core\Crypto;
use BlockHarbor\Tests\DatabaseTestCase;

final class CryptoTest extends DatabaseTestCase
{
    public function test_encrypt_then_decrypt_roundtrip(): void
    {
        $crypto = new Crypto($this->db->pdo(), 'master-key-for-tests-only');
        $plain = 'my-totp-secret-NBSWY3DPO5XXE3DE';
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
        $cipher = $cryptoA->encrypt('secret');

        $cryptoB = new Crypto($this->db->pdo(), 'key-b');
        $this->expectException(\RuntimeException::class);
        $cryptoB->decrypt($cipher);
    }
}
```

- [ ] **Step 2: Run test — expect FAIL (class missing)**

```bash
COMPOSER_ALLOW_SUPERUSER=1 composer test -- --filter=CryptoTest
```

- [ ] **Step 3: Write Crypto.php**

Create `src/Core/Crypto.php`:
```php
<?php declare(strict_types=1);

namespace BlockHarbor\Core;

use PDO;

/**
 * pgcrypto wrapper for symmetric encryption of small secrets
 * (TOTP secrets, recovery codes, API keys). Uses pgp_sym_encrypt which
 * includes a random IV per call — different ciphertexts for same plaintext.
 *
 * The master key is read from APP_KEY env var (32-byte hex). Rotating
 * the key requires re-encrypting all stored secrets — handled by P7 ops.
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
            throw new \RuntimeException('Decryption failed (wrong key or corrupt cipher)', 0, $e);
        }
        if (!$row || $row['p'] === null) {
            throw new \RuntimeException('pgp_sym_decrypt returned NULL — bad key or corrupt cipher');
        }
        return (string)$row['p'];
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

```bash
COMPOSER_ALLOW_SUPERUSER=1 composer test -- --filter=CryptoTest
```

Expected: 3 tests passing.

- [ ] **Step 5: Commit**

```bash
git add src/Core/Crypto.php tests/Integration/Core/CryptoTest.php
git commit -m "feat(core): add pgcrypto Crypto wrapper for secret at-rest enc

Symmetric encrypt/decrypt of TOTP secrets, recovery codes, etc.
Uses pgp_sym_encrypt (random IV per call — different ciphertexts
for same plaintext). Master key from APP_KEY env var."
git push origin main
```

---

## Task 3: AuditLogger + integration test

**Files:**
- Create: `src/Audit/AuditLogger.php`
- Create: `tests/Integration/Audit/AuditLoggerTest.php`

- [ ] **Step 1: Write failing test**

Create `tests/Integration/Audit/AuditLoggerTest.php`:
```php
<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Audit;

use BlockHarbor\Audit\AuditLogger;
use BlockHarbor\Tests\DatabaseTestCase;
use PDO;

final class AuditLoggerTest extends DatabaseTestCase
{
    public function test_log_inserts_row_with_chained_hash(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        $logger->log('user.create', ['username' => 'alice'], actor: 'admin', ip: '10.0.0.1');

        $row = $this->db->pdo()->query(
            "SELECT action, actor_username, ip_address::text AS ip,
                    details, encode(prev_hash,'hex') AS ph, encode(entry_hash,'hex') AS eh
             FROM audit_log ORDER BY id DESC LIMIT 1"
        )->fetch(PDO::FETCH_ASSOC);

        self::assertSame('user.create', $row['action']);
        self::assertSame('admin', $row['actor_username']);
        self::assertSame('10.0.0.1', $row['ip']);
        self::assertSame(['username' => 'alice'], json_decode($row['details'], true));
        self::assertSame('00', $row['ph']);              // first row → \x00
        self::assertSame(64, strlen($row['eh']));         // sha256 hex
    }

    public function test_log_omits_optional_fields(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        $logger->log('system.boot');

        $row = $this->db->pdo()->query(
            "SELECT action, actor_username, ip_address FROM audit_log ORDER BY id DESC LIMIT 1"
        )->fetch(PDO::FETCH_ASSOC);

        self::assertSame('system.boot', $row['action']);
        self::assertNull($row['actor_username']);
        self::assertNull($row['ip_address']);
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
COMPOSER_ALLOW_SUPERUSER=1 composer test -- --filter=AuditLoggerTest
```

- [ ] **Step 3: Write AuditLogger.php**

Create `src/Audit/AuditLogger.php`:
```php
<?php declare(strict_types=1);

namespace BlockHarbor\Audit;

use PDO;

/**
 * Universal audit hook. Every domain service constructor should accept an
 * AuditLogger and call log() for state-changing operations. The audit_log
 * table's BEFORE INSERT trigger computes prev_hash and entry_hash —
 * application code does not (and cannot, due to REVOKE) supply them.
 */
final class AuditLogger
{
    public function __construct(private readonly PDO $pdo) {}

    /**
     * @param array<string,mixed> $details
     */
    public function log(
        string $action,
        array $details = [],
        ?string $actor = null,
        ?string $actorRole = null,
        ?string $ip = null,
    ): void {
        $stmt = $this->pdo->prepare(
            'INSERT INTO audit_log (action, actor_username, actor_role, ip_address, details)
             VALUES (:a, :u, :r, :ip, :d::jsonb)'
        );
        $stmt->execute([
            ':a'  => $action,
            ':u'  => $actor,
            ':r'  => $actorRole,
            ':ip' => $ip,
            ':d'  => json_encode($details, JSON_THROW_ON_ERROR),
        ]);
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

Expected: 2 tests passing.

- [ ] **Step 5: Commit**

```bash
git add src/Audit/AuditLogger.php tests/Integration/Audit/AuditLoggerTest.php
git commit -m "feat(audit): add AuditLogger universal hook

One method: log(action, details, actor, role, ip). DB trigger handles
chain hashing. Every domain service constructor accepts this; emit on
state-changing operations. 2 integration tests."
git push origin main
```

---

## Task 4: ChainVerifier + tests

**Files:**
- Create: `src/Audit/ChainVerifier.php`
- Create: `tests/Integration/Audit/ChainVerifierIntegrationTest.php`

- [ ] **Step 1: Write failing test**

Create `tests/Integration/Audit/ChainVerifierIntegrationTest.php`:
```php
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

        self::assertTrue($result->ok);
        self::assertSame(5, $result->checked);
        self::assertNull($result->mismatchAtId);
    }

    public function test_verifier_detects_tampering(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        $logger->log('first', []);
        $logger->log('second', []);
        $logger->log('third', []);

        // Tamper with the middle row (action mutation; we have to use the
        // postgres superuser since the app role lacks UPDATE on audit_log
        // by design — for the test we punch through directly).
        // In production, this state never happens unless an attacker has
        // DB superuser; the test simulates the verifier's response.
        \exec('sudo -u postgres psql -d blockharbor -c "UPDATE audit_log SET action=\'TAMPERED\' WHERE id=(SELECT id FROM audit_log ORDER BY id LIMIT 1 OFFSET 1)" 2>&1', $out, $rc);

        if ($rc !== 0) {
            $this->markTestSkipped('Cannot tamper for test (need postgres superuser sudo).');
        }

        $v = new ChainVerifier($this->db->pdo());
        $result = $v->verify();

        self::assertFalse($result->ok);
        self::assertNotNull($result->mismatchAtId);
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Write ChainVerifier.php**

Create `src/Audit/ChainVerifier.php`:
```php
<?php declare(strict_types=1);

namespace BlockHarbor\Audit;

use PDO;

final class VerifyResult
{
    public function __construct(
        public readonly bool $ok,
        public readonly int $checked,
        public readonly ?int $mismatchAtId,
        public readonly ?string $mismatchReason,
    ) {}
}

final class ChainVerifier
{
    public function __construct(private readonly PDO $pdo) {}

    public function verify(?\DateTimeImmutable $since = null): VerifyResult
    {
        $sql = "SELECT id, ts, actor_username, action, details,
                       encode(prev_hash,'hex') AS ph, encode(entry_hash,'hex') AS eh
                FROM audit_log";
        $params = [];
        if ($since !== null) {
            $sql .= ' WHERE ts >= :since';
            $params[':since'] = $since->format(\DateTimeInterface::ATOM);
        }
        $sql .= ' ORDER BY id';

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        $prevHashHex = '00'; // first row's prev_hash MUST be \x00
        $checked = 0;
        foreach ($stmt as $row) {
            $checked++;

            if ($row['ph'] !== $prevHashHex) {
                return new VerifyResult(
                    false, $checked, (int)$row['id'],
                    "prev_hash mismatch: expected $prevHashHex, got {$row['ph']}",
                );
            }

            // Recompute entry_hash:
            //   sha256(prev_hash_bytes || canonical_json_utf8)
            $canonical = json_encode([
                'ts'      => $row['ts'],
                'actor'   => $row['actor_username'],
                'action'  => $row['action'],
                'details' => json_decode($row['details'], false),
            ], JSON_THROW_ON_ERROR);
            $expected = hash('sha256', hex2bin($prevHashHex) . $canonical);

            if ($expected !== $row['eh']) {
                return new VerifyResult(
                    false, $checked, (int)$row['id'],
                    "entry_hash mismatch at id={$row['id']}",
                );
            }

            $prevHashHex = $row['eh'];
        }

        return new VerifyResult(true, $checked, null, null);
    }
}
```

- [ ] **Step 4: Run test — expect first passes; second may skip**

The tamper test requires `sudo -u postgres` access; in CI it'll skip,
locally it should pass.

- [ ] **Step 5: Commit**

```bash
git add src/Audit/ChainVerifier.php tests/Integration/Audit/ChainVerifierIntegrationTest.php
git commit -m "feat(audit): add ChainVerifier tamper-detection service

Walks all audit_log rows in order, recomputes
sha256(prev_hash || canonical_json), returns first mismatch.
VerifyResult value object: (ok, checked, mismatchAtId, mismatchReason).
Optional --since cutoff for incremental scans."
git push origin main
```

---

## Task 5: bin/verify-audit-chain CLI

**Files:**
- Create: `bin/verify-audit-chain`

- [ ] **Step 1: Write the CLI**

Create `bin/verify-audit-chain`:
```bash
#!/usr/bin/env bash
#
# BlockHarbor — audit chain verifier
# Usage:
#   bin/verify-audit-chain                  # verify entire chain
#   bin/verify-audit-chain --since "2026-01-01"  # only from that date
#   bin/verify-audit-chain --quiet          # only error output
#   bin/verify-audit-chain --json           # JSON output

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $EUID -eq 0 ]]; then
    export COMPOSER_ALLOW_SUPERUSER=1
fi

exec php -r '
require __DIR__ . "/vendor/autoload.php";
\BlockHarbor\Core\Application::boot(__DIR__);

$args = $argv;
array_shift($args);
$since = null;
$quiet = false;
$json = false;
foreach ($args as $i => $a) {
    if ($a === "--since" && isset($args[$i+1])) {
        $since = new DateTimeImmutable($args[$i+1]);
    }
    if ($a === "--quiet") $quiet = true;
    if ($a === "--json")  { $json = true; $quiet = true; }
}

$cfg = \BlockHarbor\Core\Config::fromEnvFile(__DIR__ . "/.env");
$db  = new \BlockHarbor\Core\Database($cfg);
$v   = new \BlockHarbor\Audit\ChainVerifier($db->pdo());
$r   = $v->verify($since);

if ($json) {
    echo json_encode([
        "ok" => $r->ok,
        "checked" => $r->checked,
        "mismatch_at_id" => $r->mismatchAtId,
        "mismatch_reason" => $r->mismatchReason,
    ]), "\n";
    exit($r->ok ? 0 : 1);
}

if ($r->ok) {
    if (!$quiet) {
        echo "\033[1;32m✓\033[0m Chain OK — {$r->checked} entries, all hashes match.\n";
    }
    exit(0);
}

fwrite(STDERR, "\033[1;31m✗ Chain MISMATCH at audit_log.id={$r->mismatchAtId}: {$r->mismatchReason}\033[0m\n");
exit(1);
' -- "$@"
```

- [ ] **Step 2: chmod + smoke**

```bash
chmod +x bin/verify-audit-chain
bin/verify-audit-chain
# Expected: "✓ Chain OK — N entries, all hashes match."

bin/verify-audit-chain --json
# Expected: {"ok":true,"checked":N,"mismatch_at_id":null,...}
```

- [ ] **Step 3: Commit**

```bash
git add bin/verify-audit-chain
git commit -m "feat(audit): add bin/verify-audit-chain CLI

Bash wrapper around ChainVerifier. Supports --since, --quiet, --json.
Exit 0 = chain intact, 1 = mismatch. Suitable for cron monitoring.
Already registered in install.sh Step 9 (weekly Sunday 04:00)."
git push origin main
```

---

## Task 6: Migration `user_totp`

**Files:**
- Create: `db/migrations/20260611120000_create_user_totp.php`

- [ ] **Step 1: Write migration**

```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateUserTotp extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE user_totp (
                id                       bigserial PRIMARY KEY,
                user_id                  bigint NOT NULL UNIQUE
                                            REFERENCES users(id) ON DELETE CASCADE,
                secret_encrypted         text NOT NULL,        -- pgp_sym_encrypt → base64
                recovery_codes_encrypted text NOT NULL,        -- json array of bcrypt hashes
                recovery_codes_used      integer NOT NULL DEFAULT 0,
                verified_at              timestamptz,
                created_at               timestamptz NOT NULL DEFAULT now()
            );
            CREATE INDEX user_totp_verified_idx ON user_totp (user_id) WHERE verified_at IS NOT NULL;
        SQL);
    }
}
```

- [ ] **Step 2: Run + verify**

```bash
./bin/migrate
# Verify:
PGPASSWORD="$(grep DB_MIGRATOR_PASSWORD .env | cut -d= -f2-)" \
  psql -h 127.0.0.1 -U blockharbor_migrator -d blockharbor -c "\d user_totp"
```

- [ ] **Step 3: Commit**

```bash
git add db/migrations/20260611120000_create_user_totp.php
git commit -m "feat(db): add user_totp migration

One row per user (unique user_id). Holds encrypted TOTP secret +
json array of bcrypt-hashed recovery codes. verified_at is NULL during
enrollment (before user confirms with first code), set on success."
git push origin main
```

---

## Task 7: TotpService + unit tests

**Files:**
- Create: `src/Auth/TotpService.php`
- Create: `tests/Unit/Auth/TotpServiceTest.php`

- [ ] **Step 1: Write failing test**

```php
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
        $otp = $svc->currentCode($secret);
        self::assertTrue($svc->verify($secret, $otp));
    }

    public function test_verify_rejects_wrong_code(): void
    {
        $svc = new TotpService();
        $secret = $svc->generateSecret();
        self::assertFalse($svc->verify($secret, '000000'));
    }

    public function test_provisioning_uri_includes_issuer_and_label(): void
    {
        $svc = new TotpService(issuer: 'BlockHarbor');
        $secret = $svc->generateSecret();
        $uri = $svc->provisioningUri($secret, 'alice@example.com');
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
```

- [ ] **Step 2: Write TotpService.php**

```php
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
        $totp = TOTP::createFromSecret($secret);
        $totp->setDigits($this->digits);
        $totp->setPeriod($this->period);
        return $totp->now();
    }

    public function verify(string $secret, string $code): bool
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setDigits($this->digits);
        $totp->setPeriod($this->period);
        // Accept current ±1 period (≈30s) for clock drift.
        return $totp->verify($code, leeway: $this->period);
    }

    public function provisioningUri(string $secret, string $label): string
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setLabel($label);
        $totp->setIssuer($this->issuer);
        $totp->setDigits($this->digits);
        $totp->setPeriod($this->period);
        return $totp->getProvisioningUri();
    }

    /** @return list<string> 10 codes in XXXX-XXXX format */
    public function generateRecoveryCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $codes[] = $this->randomCode() . '-' . $this->randomCode();
        }
        return $codes;
    }

    private function randomCode(): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $out = '';
        for ($i = 0; $i < 4; $i++) {
            $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return $out;
    }
}
```

- [ ] **Step 3: Run tests — expect PASS (5 tests)**

- [ ] **Step 4: Commit**

```bash
git add src/Auth/TotpService.php tests/Unit/Auth/TotpServiceTest.php
git commit -m "feat(auth): add TotpService (RFC 6238 + recovery codes)

- generateSecret() / currentCode() / verify() with ±1 period leeway
- provisioningUri() for QR codes (issuer=BlockHarbor)
- generateRecoveryCodes(): 10 XXXX-XXXX one-time codes
- 5 unit tests"
git push origin main
```

---

## Task 8: UserTotpRepository + integration tests

**Files:**
- Create: `src/Auth/UserTotpRepository.php`
- Create: `tests/Integration/Auth/UserTotpRepositoryTest.php`

- [ ] **Step 1: Write failing test**

```php
<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\UserTotpRepository;
use BlockHarbor\Core\Crypto;
use BlockHarbor\Tests\DatabaseTestCase;

final class UserTotpRepositoryTest extends DatabaseTestCase
{
    private UserTotpRepository $repo;
    private int $userId;

    protected function setUp(): void
    {
        parent::setUp();
        $crypto = new Crypto($this->db->pdo(), 'test-master-key');
        $this->repo = new UserTotpRepository($this->db->pdo(), $crypto);

        $this->db->pdo()->exec("INSERT INTO users (username, role) VALUES ('alice', 'admin')");
        $this->userId = (int)$this->db->pdo()->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();
    }

    public function test_enroll_and_decrypt_secret(): void
    {
        $this->repo->enroll($this->userId, 'NBSWY3DPO5XXE3DE', ['code-a', 'code-b']);

        $secret = $this->repo->getSecret($this->userId);
        self::assertSame('NBSWY3DPO5XXE3DE', $secret);

        $codes = $this->repo->getRecoveryCodes($this->userId);
        self::assertCount(2, $codes);
    }

    public function test_mark_verified(): void
    {
        $this->repo->enroll($this->userId, 'S', []);
        self::assertFalse($this->repo->isVerified($this->userId));

        $this->repo->markVerified($this->userId);
        self::assertTrue($this->repo->isVerified($this->userId));
    }

    public function test_consume_recovery_code_removes_it(): void
    {
        $this->repo->enroll($this->userId, 'S', ['code-a', 'code-b', 'code-c']);
        self::assertTrue($this->repo->consumeRecoveryCode($this->userId, 'code-b'));
        self::assertFalse($this->repo->consumeRecoveryCode($this->userId, 'code-b'));
        $remaining = $this->repo->getRecoveryCodes($this->userId);
        self::assertCount(2, $remaining);
    }
}
```

- [ ] **Step 2: Write UserTotpRepository.php**

```php
<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use BlockHarbor\Core\Crypto;
use PDO;

final class UserTotpRepository
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly Crypto $crypto,
    ) {}

    /** @param list<string> $recoveryCodes plaintext codes (will be hashed) */
    public function enroll(int $userId, string $secret, array $recoveryCodes): void
    {
        $hashedCodes = array_map(
            static fn(string $c) => password_hash($c, PASSWORD_BCRYPT),
            $recoveryCodes,
        );
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_totp (user_id, secret_encrypted, recovery_codes_encrypted)
             VALUES (:u, :s, :c)
             ON CONFLICT (user_id) DO UPDATE SET
                secret_encrypted = EXCLUDED.secret_encrypted,
                recovery_codes_encrypted = EXCLUDED.recovery_codes_encrypted,
                recovery_codes_used = 0,
                verified_at = NULL'
        );
        $stmt->execute([
            ':u' => $userId,
            ':s' => $this->crypto->encrypt($secret),
            ':c' => $this->crypto->encrypt(json_encode($hashedCodes, JSON_THROW_ON_ERROR)),
        ]);
    }

    public function getSecret(int $userId): ?string
    {
        $stmt = $this->pdo->prepare('SELECT secret_encrypted FROM user_totp WHERE user_id = :u');
        $stmt->execute([':u' => $userId]);
        $cipher = $stmt->fetchColumn();
        return $cipher === false ? null : $this->crypto->decrypt((string)$cipher);
    }

    /** @return list<string> hashed codes still valid */
    public function getRecoveryCodes(int $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT recovery_codes_encrypted FROM user_totp WHERE user_id = :u');
        $stmt->execute([':u' => $userId]);
        $cipher = $stmt->fetchColumn();
        if ($cipher === false) return [];
        return json_decode($this->crypto->decrypt((string)$cipher), true) ?? [];
    }

    public function consumeRecoveryCode(int $userId, string $plainCode): bool
    {
        $hashed = $this->getRecoveryCodes($userId);
        foreach ($hashed as $i => $h) {
            if (password_verify($plainCode, $h)) {
                unset($hashed[$i]);
                $hashed = array_values($hashed);
                $stmt = $this->pdo->prepare(
                    'UPDATE user_totp
                     SET recovery_codes_encrypted = :c,
                         recovery_codes_used = recovery_codes_used + 1
                     WHERE user_id = :u'
                );
                $stmt->execute([
                    ':c' => $this->crypto->encrypt(json_encode($hashed, JSON_THROW_ON_ERROR)),
                    ':u' => $userId,
                ]);
                return true;
            }
        }
        return false;
    }

    public function markVerified(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_totp SET verified_at = now() WHERE user_id = :u'
        );
        $stmt->execute([':u' => $userId]);
    }

    public function isVerified(int $userId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT verified_at IS NOT NULL FROM user_totp WHERE user_id = :u'
        );
        $stmt->execute([':u' => $userId]);
        return (bool)$stmt->fetchColumn();
    }
}
```

- [ ] **Step 3: Run tests — expect PASS (3 tests)**

- [ ] **Step 4: Commit**

```bash
git add src/Auth/UserTotpRepository.php tests/Integration/Auth/UserTotpRepositoryTest.php
git commit -m "feat(auth): add UserTotpRepository with bcrypt recovery + pgcrypto secret

ON CONFLICT (user_id) DO UPDATE — re-enrollment clears prior state.
consumeRecoveryCode: one-time use; verified via password_verify (bcrypt).
3 integration tests."
git push origin main
```

---

## Tasks 9–13: TOTP UI flow

These tasks build the UI on top of TotpService + UserTotpRepository.
Detailed steps follow the same TDD pattern. Summary:

### Task 9: `MfaState` enum + `AuthResult` extension
Add `RequiresMfa` to `AuthResult`. Add new `MfaState` enum: `NotRequired | TotpRequired | PasskeyRequired | EitherRequired`. Modify `AuthService::attempt()` to call `MfaResolver::resolve($user)` after password success: if NotRequired → return Success; else stash `pending_user_id` in `$_SESSION` and return `RequiresMfa`.

### Task 10: `LoginController` step-up integration
On `RequiresMfa`, redirect to `/2fa` instead of `/dashboard`.

### Task 11: `TwoFactorController` + view
- GET `/2fa` — render `auth/2fa-totp.php` form (or passkey choice if user has both)
- POST `/2fa` — verify code via `TotpService::verify(secret, code)`; on success, promote `pending_user_id` → `user_id` and redirect to `/dashboard`; on failure, audit-log + flash error + redirect back

### Task 12: `TwoFactorSetupController` + views
- First-time enrollment for users where `mfa_required=true` but no `user_totp` row exists
- GET `/2fa/setup` — generate secret + recovery codes, store unverified, render QR + recovery codes (show once)
- POST `/2fa/setup` — verify first code → markVerified

### Task 13: Forced setup for admin role
If user has `role='admin'` and no verified TOTP row, redirect to `/2fa/setup` instead of `/dashboard`.

---

## Tasks 14–17: WebAuthn / Passkeys

### Task 14: Migration `user_passkeys`

```php
CREATE TABLE user_passkeys (
    id              bigserial PRIMARY KEY,
    user_id         bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   bytea  NOT NULL UNIQUE,
    public_key      bytea  NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    transports      text[],
    aaguid          uuid,
    label           varchar(64),
    last_used_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_passkeys_user_idx ON user_passkeys (user_id);
```

### Task 15: `WebAuthnService` + registration ceremony
Wrap `web-auth/webauthn-lib`. Methods: `createRegistrationOptions(User) → array`, `verifyRegistration(challenge, response) → bool + persist`.

### Task 16: `PasskeyController::register` GET+POST flow
Render setup page with JavaScript that calls navigator.credentials.create() with the options from `createRegistrationOptions`; POST the result back.

### Task 17: `WebAuthnService` assertion + `PasskeyController::assert`
The login ceremony. Add `/2fa/passkey` route that does `createAssertionOptions` then verifies.

---

## Tasks 18–19: Risk Scoring

### Task 18: Migration `user_ip_allowlist` + `risk_events`

```php
CREATE TABLE user_ip_allowlist (
    id         bigserial PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cidr       inet NOT NULL,
    label      varchar(64),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE risk_event_type AS ENUM ('new_ip', 'new_country', 'new_ua', 'atypical_hour');

CREATE TABLE risk_events (
    id          bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id  uuid REFERENCES user_sessions(id),
    event_type  risk_event_type NOT NULL,
    score       smallint NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX risk_events_user_time ON risk_events (user_id, created_at DESC);
```

### Task 19: `RiskScorer` service + unit tests

```php
<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use PDO;

final class RiskScorer
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly ?\GeoIp2\Database\Reader $geo = null,
    ) {}

    /** @return array{score:int, events:list<array{type:string,score:int}>} */
    public function evaluate(int $userId, string $ip, ?string $userAgent): array
    {
        $events = [];
        $score = 0;

        // Rule 1: new IP for this user (+30)
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM login_attempts
             WHERE username = (SELECT username FROM users WHERE id = :u)
               AND ip_address = :ip AND success = true LIMIT 1'
        );
        $stmt->execute([':u' => $userId, ':ip' => $ip]);
        if ($stmt->fetchColumn() === false) {
            $events[] = ['type' => 'new_ip', 'score' => 30];
            $score += 30;
        }

        // Rule 2: new country (+40) — only if GeoIP2 reader available
        if ($this->geo !== null) {
            try {
                $country = $this->geo->country($ip)->country->isoCode;
                $stmt = $this->pdo->prepare(
                    "SELECT 1 FROM login_attempts
                     WHERE username = (SELECT username FROM users WHERE id = :u)
                       AND geo_country = :c AND success = true LIMIT 1"
                );
                $stmt->execute([':u' => $userId, ':c' => $country]);
                if ($stmt->fetchColumn() === false) {
                    $events[] = ['type' => 'new_country', 'score' => 40];
                    $score += 40;
                }
            } catch (\Throwable) {
                // GeoIP lookup failed (private IP, missing db) — skip rule
            }
        }

        // Rule 3: new UA family (+20) — naive parse (Chrome/Firefox/Safari/...)
        if ($userAgent !== null) {
            $family = $this->parseUaFamily($userAgent);
            $stmt = $this->pdo->prepare(
                "SELECT 1 FROM login_attempts
                 WHERE username = (SELECT username FROM users WHERE id = :u)
                   AND success = true AND user_agent LIKE :pat LIMIT 1"
            );
            $stmt->execute([':u' => $userId, ':pat' => "%$family%"]);
            if ($stmt->fetchColumn() === false) {
                $events[] = ['type' => 'new_ua', 'score' => 20];
                $score += 20;
            }
        }

        // Rule 4: atypical hour (+10) — ±3h of avg of last 30 successful
        $stmt = $this->pdo->prepare(
            'SELECT EXTRACT(HOUR FROM created_at) FROM login_attempts
             WHERE username = (SELECT username FROM users WHERE id = :u)
               AND success = true ORDER BY id DESC LIMIT 30'
        );
        $stmt->execute([':u' => $userId]);
        $hours = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
        if (count($hours) >= 5) {
            $avg = array_sum($hours) / count($hours);
            $now = (int)date('G');
            if (abs($now - $avg) > 3 && abs($now - $avg) < 21) {
                $events[] = ['type' => 'atypical_hour', 'score' => 10];
                $score += 10;
            }
        }

        return ['score' => $score, 'events' => $events];
    }

    private function parseUaFamily(string $ua): string
    {
        foreach (['Firefox', 'Edge', 'Chrome', 'Safari', 'Opera'] as $f) {
            if (str_contains($ua, $f)) return $f;
        }
        return 'Other';
    }
}
```

Tests cover each rule individually + the threshold (60 = step-up).

---

## Task 20: AuthService MFA integration

**Files:**
- Modify: `src/Auth/AuthResult.php` — add `RequiresMfa`, `RequiresMfaSetup`
- Modify: `src/Auth/AuthService.php` — call MFA resolver after password success
- Create: `src/Auth/MfaResolver.php`
- Create: `tests/Integration/Auth/AuthServiceMfaTest.php`

Detail: after `recordSuccessfulLogin`, if `MfaResolver::needsStepUp(user, riskScore)` returns true, return `AttemptOutcome(RequiresMfa, user)` instead of `Success`. Controller redirects to `/2fa`.

---

## Task 21: Wire AuditLogger into all auth services

**Files:**
- Modify: `src/Auth/AuthService.php` — log `login.success`, `login.failure`, `account.locked`
- Modify: `src/Auth/UserRepository.php` — log `user.create`, `user.password_changed`, `user.locked`, `user.unlocked`
- Modify: `src/Auth/Controllers/LoginController.php` — log `session.start`, `session.end`
- Modify: `src/Auth/Controllers/TwoFactorController.php` — log `mfa.success`, `mfa.failure`
- Modify: `src/Core/Application.php` — construct + inject AuditLogger into all resolvers

Tests verify audit row created with expected action+actor for each path.

---

## Task 22: bin/cleanup-mfa-tokens cron

Drops `user_totp` rows where `verified_at IS NULL AND created_at < now() - interval '24h'` (abandoned enrollments).

---

## Task 23: P2 Sign-off + Tag

- [ ] `composer test` → all green (~70 tests target)
- [ ] `composer stan` → clean
- [ ] `composer psalm` → 98%+ inferred
- [ ] Manual: enroll TOTP via /2fa/setup → log out → log in → enter code → /dashboard
- [ ] Manual: trigger new-IP scenario via VPN → step-up forced
- [ ] `bin/verify-audit-chain` → ✓ Chain OK
- [ ] Tag `v0.1.0-p2` with notes:

```
v0.1.0-p2 — Audit + 2FA + Passkeys

Adds:
- AuditLogger universal hook injected into every auth service
- bin/verify-audit-chain CLI (cron-scheduled weekly)
- 4 new tables: user_totp, user_passkeys, user_ip_allowlist, risk_events
- TOTP 2FA (RFC 6238) with 10 recovery codes (bcrypt hashed)
- WebAuthn/FIDO2 passkeys (registration + assertion)
- RiskScorer (rule-based: new IP/country/UA/hour → score 0-100)
- Step-up auth flow (password → /2fa → /dashboard)
- pgcrypto secret encryption (BlockHarbor\Core\Crypto)

Verified:
- Audit chain intact across all login flows
- TOTP enroll + verify + recovery code consumption
- WebAuthn registration + assertion in Chrome + Safari
- Step-up forced on new IP (manual VPN test)
```

---

## Self-review checklist

- [ ] **Spec coverage:** §5 (auth) + §6 (audit) of design spec fully implemented
- [ ] **PHP 8.1 compatibility:** no 8.3-only syntax (no `readonly class`, no typed class constants)
- [ ] **PSR-4 namespace:** all under `BlockHarbor\`, mapping correct
- [ ] **Naming:** `BlockHarbor` PascalCase in code, `blockharbor` lowercase in URLs/DB
- [ ] **Audit consistency:** every state-changing service method has a corresponding `audit_log` row
- [ ] **Tests:** TDD pattern; ≥3 tests per new class; integration test for every repository
- [ ] **Static analysis:** PHPStan L8 + Psalm clean after each task
- [ ] **No new front-end deps:** Alpine + HTMX via CDN as in P1

---

## Estimated effort

- Tasks 1–5 (Audit core): ~3 hours
- Tasks 6–13 (TOTP path): ~5 hours
- Tasks 14–17 (WebAuthn): ~4 hours (most complex — JS interop)
- Tasks 18–19 (Risk): ~2 hours
- Tasks 20–22 (Integration + cleanup): ~3 hours
- Task 23 (sign-off): ~1 hour

**Total: ~18 hours** of focused work. Roughly 1 working day if uninterrupted; realistically 2–3 days spread across sessions.

---

## Plan complete — execution choice

Plan complete and saved to `docs/superpowers/plans/2026-06-11-blockharbor-p2-audit-2fa-passkeys.md`.

Two execution options:

**1. Subagent-Driven** — Fresh subagent per task. Per `[[feedback-subagent-overhead]]`, use this only for genuinely multi-file tasks (e.g. Tasks 15, 16, 17 — WebAuthn JS interop).

**2. Inline Execution (recommended for most P2 tasks)** — Controller-only TDD loop. Faster for the 12+ single-file Audit + TOTP + repository tasks.

Default suggestion: hybrid — inline for tasks 1–13, 18–19, 21–22; subagent for 14–17 (WebAuthn complexity); inline for 20, 23. Switch the plan execution mode mid-stream as needed.

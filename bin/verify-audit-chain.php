<?php declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Parse args (--since, --quiet, --json)
$since = null;
$quiet = false;
$json  = false;
for ($i = 1; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--since' && isset($argv[$i + 1])) {
        $since = new \DateTimeImmutable($argv[++$i]);
    } elseif ($arg === '--quiet') {
        $quiet = true;
    } elseif ($arg === '--json') {
        $json = true; $quiet = true;
    } elseif ($arg === '-h' || $arg === '--help') {
        echo "Usage: bin/verify-audit-chain [--since DATE] [--quiet] [--json]\n";
        exit(0);
    }
}

$root   = dirname(__DIR__);
$config = \BlockHarbor\Core\Config::fromEnvFile($root . '/.env');
$db     = new \BlockHarbor\Core\Database($config);
$v      = new \BlockHarbor\Audit\ChainVerifier($db->pdo());
$result = $v->verify($since);

if ($json) {
    echo json_encode([
        'ok'              => $result->ok,
        'checked'         => $result->checked,
        'mismatch_at_id'  => $result->mismatchAtId,
        'mismatch_reason' => $result->mismatchReason,
    ], JSON_THROW_ON_ERROR), "\n";
    exit($result->ok ? 0 : 1);
}

if ($result->ok) {
    if (!$quiet) {
        $g = "\033[1;32m";
        $r = "\033[0m";
        echo "{$g}✓{$r} Chain OK — {$result->checked} entries, all hashes match.\n";
    }
    exit(0);
}

$rd = "\033[1;31m";
$rs = "\033[0m";
fwrite(STDERR,
    "{$rd}✗ Chain MISMATCH at audit_log.id={$result->mismatchAtId}: {$result->mismatchReason}{$rs}\n"
);
exit(1);

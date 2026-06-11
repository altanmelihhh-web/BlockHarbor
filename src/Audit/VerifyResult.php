<?php declare(strict_types=1);

namespace BlockHarbor\Audit;

final class VerifyResult
{
    public function __construct(
        public readonly bool $ok,
        public readonly int $checked,
        public readonly ?int $mismatchAtId,
        public readonly ?string $mismatchReason,
    ) {}
}

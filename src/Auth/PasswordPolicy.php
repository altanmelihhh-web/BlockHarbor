<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

final class PasswordPolicy
{
    public function __construct(
        private readonly int  $minLength = 12,
        private readonly bool $requireMixedCase = true,
        private readonly bool $requireDigit = true,
        private readonly bool $requireSpecial = true,
    ) {}

    /** @return list<string> error codes; empty array = OK */
    public function validate(string $password): array
    {
        $errors = [];

        if (strlen($password) < $this->minLength) {
            $errors[] = 'too_short';
        }
        if ($this->requireMixedCase &&
            !(preg_match('/[a-z]/', $password) && preg_match('/[A-Z]/', $password))) {
            $errors[] = 'missing_mixed_case';
        }
        if ($this->requireDigit && !preg_match('/\d/', $password)) {
            $errors[] = 'missing_digit';
        }
        if ($this->requireSpecial && !preg_match('/[^\w\s]/', $password)) {
            $errors[] = 'missing_special';
        }

        return $errors;
    }
}

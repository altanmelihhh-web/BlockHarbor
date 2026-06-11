<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use DateTimeImmutable;

final class AuthService
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly LoginAttemptRepository $attempts,
        private readonly PasswordHasher $hasher,
        private readonly int $maxFailsPerIpIn5Min,
        private readonly int $maxFailsPerUserIn1h,
        private readonly int $lockoutMinutes,
        private readonly ?MfaResolver $mfa = null,
    ) {}

    public function attempt(string $username, string $password, string $ip, ?string $userAgent): AttemptOutcome
    {
        // 1. IP rate limit — must be checked BEFORE user lookup to prevent
        //    user-enumeration via timing differences.
        if ($this->attempts->countFailuresByIp($ip, 300) >= $this->maxFailsPerIpIn5Min) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'rate_limited_ip', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::RateLimited, null);
        }

        $user = $this->users->findByUsername($username);

        // 2. Unknown user — return BadCredentials (NOT 'unknown_user' visible
        //    to the client) to prevent enumeration.
        if ($user === null) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'unknown_user', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::BadCredentials, null);
        }

        if (!$user->active) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'inactive', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::Inactive, null);
        }

        // 3. Lockout — check BEFORE password verify so a locked account
        //    cannot be probed for the right password.
        if ($user->isLocked()) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'locked', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::Locked, null);
        }

        // 4. Password verify.
        if (!$this->hasher->verify($password, $user->passwordHash ?? '')) {
            $newCount = $this->users->incrementFailedLoginCount($user->id);
            if ($newCount >= $this->maxFailsPerUserIn1h) {
                $this->users->lockUntil(
                    $user->id,
                    new DateTimeImmutable('+' . $this->lockoutMinutes . ' minutes'),
                );
            }
            $this->attempts->record($username, $ip, success: false, failureReason: 'bad_password', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::BadCredentials, null);
        }

        // 5. Password OK: reset counters, record successful attempt,
        //    re-read user (last_login_at now set).
        $this->users->recordSuccessfulLogin($user->id);
        $this->attempts->record($username, $ip, success: true, failureReason: null, userAgent: $userAgent);
        $fresh = $this->users->findById($user->id);

        // 6. MFA gate: if a resolver is installed and the user has an
        //    enrolled factor, return RequiresMfa instead of Success. The
        //    LoginController stashes pending_user_id and redirects to /2fa;
        //    only after MFA verification does pending_user_id → user_id.
        if ($this->mfa !== null && $fresh !== null) {
            $state = $this->mfa->resolve($fresh);
            if ($state !== MfaState::NotRequired) {
                return new AttemptOutcome(AuthResult::RequiresMfa, $fresh);
            }
        }

        return new AttemptOutcome(AuthResult::Success, $fresh);
    }
}

final class AttemptOutcome
{
    public function __construct(
        public readonly AuthResult $result,
        public readonly ?User $user,
    ) {}
}

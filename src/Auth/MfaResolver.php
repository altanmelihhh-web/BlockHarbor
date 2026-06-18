<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use PDO;

/**
 * Decides whether a user needs to complete an MFA challenge after a
 * successful password verify, and which factor(s) they can use.
 *
 * Policy-vs-state separation:
 *   - "Should this user have MFA?" (policy) — admin role OR users.mfa_required.
 *     If yes but no factor enrolled, that's a SETUP problem handled by
 *     TwoFactorSetupController (not this class).
 *   - "What factor can this user use right now?" (state) — what's actually
 *     enrolled. This class answers that.
 *
 * For users with no enrollment, returns NotRequired. The forced-setup
 * redirect lives in the controller layer.
 */
final class MfaResolver
{
    public function __construct(private readonly PDO $pdo) {}

    public function resolve(User $user): MfaState
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM user_totp WHERE user_id = :u AND verified_at IS NOT NULL LIMIT 1'
        );
        $stmt->execute([':u' => $user->id]);
        $hasTotp = (bool)$stmt->fetchColumn();

        // Check passkey table only if it exists (P2 Task 14 lands it).
        $hasPasskey = false;
        $check = $this->pdo->prepare("SELECT to_regclass('public.user_passkeys')");
        $check->execute();
        if ($check->fetchColumn() !== null) {
            $pk = $this->pdo->prepare('SELECT 1 FROM user_passkeys WHERE user_id = :u LIMIT 1');
            $pk->execute([':u' => $user->id]);
            $hasPasskey = (bool)$pk->fetchColumn();
        }

        return match (true) {
            $hasTotp && $hasPasskey => MfaState::EitherRequired,
            $hasTotp                => MfaState::TotpRequired,
            $hasPasskey             => MfaState::PasskeyRequired,
            default                 => MfaState::NotRequired,
        };
    }

    /**
     * Policy check: would the system PREFER this user to have MFA, even
     * if they don't yet have a factor enrolled? Used by the controller to
     * decide whether to redirect to /2fa/setup vs /dashboard.
     */
    public function policyRequires(User $user): bool
    {
        return $user->role === 'admin' || $user->mfaRequired;
    }
}

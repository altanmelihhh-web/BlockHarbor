<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

/**
 * What MFA challenge does this user need to complete?
 *
 * NotRequired:     user has no MFA enrolled AND policy doesn't force it
 *                  (or is currently forced into setup-flow, handled by
 *                  TwoFactorSetupController — that's a separate concern)
 * TotpRequired:    user has a verified TOTP row but no passkeys
 * PasskeyRequired: user has at least one passkey but no verified TOTP
 * EitherRequired:  user has both — UI lets them pick
 */
enum MfaState: string
{
    case NotRequired     = 'not_required';
    case TotpRequired    = 'totp_required';
    case PasskeyRequired = 'passkey_required';
    case EitherRequired  = 'either_required';
}

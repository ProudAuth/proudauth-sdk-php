<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * Verification error categories, identical to the Node SDK's
 * VERIFIER_ERROR_CODES. They are stable, safe to log and never contain token
 * material, secrets or claim values (SDK-008). Use them as telemetry
 * dimensions: `$e->errorCode->value`.
 */
enum VerifierErrorCode: string
{
    case MissingToken = 'missing_token';
    case InvalidRequest = 'invalid_request';
    case Malformed = 'malformed';
    case TooLarge = 'too_large';
    case DuplicateClaim = 'duplicate_claim';
    case TokenType = 'token_type';
    case Algorithm = 'algorithm';
    case UnknownKey = 'unknown_key';
    case Signature = 'signature';
    case Issuer = 'issuer';
    case Audience = 'audience';
    case Expired = 'expired';
    case NotYetValid = 'not_yet_valid';
    case FutureIssued = 'future_issued';
    case TokenKind = 'token_kind';
    case SenderConstraint = 'sender_constraint';
    case Inactive = 'inactive';
    case Unavailable = 'unavailable';
    case Organization = 'organization';
    case Scope = 'scope';
    case SupportPolicy = 'support_policy';
    case Contract = 'contract';
    case StaleState = 'stale_state';
    case Revoked = 'revoked';

    /** The fixed, token-free message for this category. */
    public function message(): string
    {
        return match ($this) {
            self::MissingToken => 'missing bearer token',
            self::InvalidRequest => 'bearer token must be sent in the Authorization header, not the query string',
            self::Malformed => 'malformed token',
            self::TooLarge => 'token too large',
            self::DuplicateClaim => 'duplicate JSON member',
            self::TokenType => 'wrong token type',
            self::Algorithm => 'algorithm not allowed',
            self::UnknownKey => 'unknown signing key',
            self::Signature => 'invalid signature',
            self::Issuer => 'untrusted issuer',
            self::Audience => 'wrong audience',
            self::Expired => 'token expired',
            self::NotYetValid => 'token not yet valid',
            self::FutureIssued => 'token issued in the future',
            self::TokenKind => 'token kind not accepted',
            self::SenderConstraint => 'sender constraint not satisfied',
            self::Inactive => 'token is not active',
            self::Unavailable => 'verification dependency unavailable',
            self::Organization => 'organization mismatch',
            self::Scope => 'required scope missing',
            self::SupportPolicy => 'support access not permitted for this operation',
            self::Contract => 'support contract not satisfied (auditor required)',
            self::StaleState => 'revocation state is older than the configured bound',
            self::Revoked => 'session or subject was revoked',
        };
    }
}

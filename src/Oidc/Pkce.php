<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

use ProudAuth\Sdk\Internal\Base64Url;

/**
 * PKCE and related helpers.
 */
final class Pkce
{
    /** A URL-safe random value with 256 bits of entropy (state, nonce, PKCE verifier). */
    public static function randomValue(): string
    {
        return Base64Url::encode(random_bytes(32));
    }

    /** The S256 PKCE challenge for a verifier (RFC 7636). */
    public static function challenge(string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }

    /**
     * at_hash / c_hash: the left half of the hash matching the signing
     * algorithm (OIDC Core §3.1.3.6); SHA-512 for EdDSA, SHA-256 otherwise.
     */
    public static function halfHash(string $alg, string $value): string
    {
        $d = hash($alg === 'EdDSA' ? 'sha512' : 'sha256', $value, true);
        return Base64Url::encode(substr($d, 0, intdiv(strlen($d), 2)));
    }
}

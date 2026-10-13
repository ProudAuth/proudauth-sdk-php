<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * Multi-issuer applications (INT-009): tokens from several explicitly
 * registered issuers, for example one realm per customer. The token's `iss`
 * only selects the registration; that issuer's Verifier then checks
 * everything, `iss` included. A validly signed token from any other issuer is
 * refused, even when its subject or email matches a known user. Subjects are
 * unique per issuer only: key application records by (tenant, subject).
 */
final class MultiIssuerVerifier implements Authenticator
{
    /** @var array<string, IssuerRegistration> */
    private readonly array $issuers;

    /**
     * @param array<string, IssuerRegistration> $registrations keyed by exact issuer URL
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $registrations)
    {
        $issuers = [];
        foreach ($registrations as $iss => $reg) {
            $iss = (string) $iss;
            if ($iss === '' || !$reg instanceof IssuerRegistration || $reg->tenant === '' || $reg->verifier->issuer !== $iss) {
                throw new \InvalidArgumentException('verifier: each registration needs a tenant and a verifier configured for exactly that issuer');
            }
            $issuers[$iss] = $reg;
        }
        if ($issuers === []) {
            throw new \InvalidArgumentException('verifier: register at least one issuer');
        }
        $this->issuers = $issuers;
    }

    /**
     * Verifies a token and returns its claims with the issuer's tenant.
     *
     * @throws VerifierException
     */
    public function verifyTenant(string $raw): TenantClaims
    {
        $reg = $this->issuers[self::unverifiedIssuer($raw)] ?? null;
        if ($reg === null) {
            throw new VerifierException(VerifierErrorCode::Issuer);
        }
        return new TenantClaims($reg->verifier->verify($raw), $reg->tenant);
    }

    /** Authenticator interface; prefer verifyTenant() where tenants matter. */
    public function authenticate(string $raw): Claims
    {
        return $this->verifyTenant($raw)->claims;
    }

    /** Reads iss only to choose a verifier; nothing else in the unverified payload is used. */
    private static function unverifiedIssuer(string $raw): string
    {
        if (strlen($raw) > 16 << 10) {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        $parts = explode('.', $raw);
        if (count($parts) !== 3) {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        $json = base64_decode(strtr($parts[1], '-_', '+/'));
        $payload = $json === false ? null : json_decode($json, true, 512, JSON_INVALID_UTF8_SUBSTITUTE);
        $iss = is_array($payload) ? ($payload['iss'] ?? null) : null;
        if (!is_string($iss) || $iss === '') {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        return $iss;
    }
}

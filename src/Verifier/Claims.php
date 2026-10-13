<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * The verified security context of one request. Instances are immutable.
 *
 * Organization and object ownership remain resource-server decisions: compare
 * `$orgId` with the organization of the resource taken from your own data
 * (`requireOrganization()`), never with an identifier from the request.
 */
final class Claims
{
    /** @var list<string> */
    public readonly array $scopes;

    /**
     * Use named arguments; the optional members default to "absent".
     *
     * @param list<string> $scopes
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $subject,
        public readonly string $audience,
        public readonly string $clientId,
        array $scopes,
        public readonly string $orgId,
        public readonly string $sessionId,
        public readonly string $tokenKind,
        public readonly string $jti,
        public readonly string $acr,
        /** Authorization revision; only meaningful when compared with trusted current state. */
        public readonly int|float $authzVersion,
        /** True when live server state was consulted (introspection). */
        public readonly bool $online,
        public readonly ?\DateTimeImmutable $issuedAt = null,
        public readonly ?\DateTimeImmutable $expiry = null,
        public readonly ?\DateTimeImmutable $authTime = null,
        public readonly ?Actor $actor = null,
        /** "read_only" or "allowlisted_write" for support tokens (strict-online only). */
        public readonly string $supportMode = '',
        public readonly string $impersonationGrantId = '',
    ) {
        $this->scopes = array_values($scopes);
    }

    /** Reports whether the token carries the scope. */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * Throws a Scope VerifierException unless every listed scope is present.
     * The exception carries the required scopes (for the WWW-Authenticate
     * challenge).
     *
     * @throws VerifierException
     */
    public function requireScope(string ...$scopes): void
    {
        foreach ($scopes as $s) {
            if (!$this->hasScope($s)) {
                throw new VerifierException(VerifierErrorCode::Scope, null, array_values($scopes));
            }
        }
    }

    /**
     * Matches the verified organization context with the organization that
     * owns the requested resource, taken from the service's own trusted data
     * (§14.4 step 8, TEST-007/008). Throws an Organization VerifierException on
     * any mismatch, including when either side is empty.
     *
     * @throws VerifierException
     */
    public function requireOrganization(string $resourceOrgId): void
    {
        if ($this->orgId === '' || $resourceOrgId === '' || $this->orgId !== $resourceOrgId) {
            throw new VerifierException(VerifierErrorCode::Organization);
        }
    }

    /** Reports whether this is a support (impersonation) request. */
    public function isSupport(): bool
    {
        return $this->tokenKind === 'impersonation_access';
    }
}

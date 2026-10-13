<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * Verified claims together with the tenant registered for their issuer.
 */
final class TenantClaims
{
    public function __construct(
        public readonly Claims $claims,
        public readonly string $tenant,
    ) {
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * One issuer of a MultiIssuerVerifier: its Verifier and the application's own
 * tenant for tokens of that issuer.
 */
final class IssuerRegistration
{
    public function __construct(
        public readonly Verifier $verifier,
        public readonly string $tenant,
    ) {
    }
}

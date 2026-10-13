<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * Turns a raw bearer token into verified claims. Implemented by Verifier
 * (offline), MultiIssuerVerifier, Introspector (strict-online),
 * BoundedVerifier and the per-route authenticators of SupportGuard::route().
 */
interface Authenticator
{
    /**
     * @throws VerifierException
     */
    public function authenticate(string $raw): Claims;
}

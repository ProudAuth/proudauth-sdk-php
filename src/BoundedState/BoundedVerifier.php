<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\BoundedState;

use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;

/**
 * Offline verification followed by a bounded-state check.
 */
final class BoundedVerifier implements Authenticator
{
    public function __construct(
        public readonly Authenticator $verifier,
        public readonly BoundedState $state,
    ) {
    }

    public function authenticate(string $raw): Claims
    {
        $claims = $this->verifier->authenticate($raw);
        $this->state->check($claims);
        return $claims;
    }
}

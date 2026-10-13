<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Introspection;

use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;

/**
 * One route of a SupportGuard as an Authenticator (see SupportGuard::route()).
 */
final class RouteAuthenticator implements Authenticator
{
    /** @internal use SupportGuard::route() */
    public function __construct(
        private readonly SupportGuard $guard,
        public readonly string $operation,
        public readonly bool $read,
    ) {
    }

    public function authenticate(string $raw): Claims
    {
        return $this->guard->authorizeAny($raw, $this->operation, $this->read);
    }
}

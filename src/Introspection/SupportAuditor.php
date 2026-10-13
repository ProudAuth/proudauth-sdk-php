<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Introspection;

/**
 * Persists support evidence. It is called BEFORE access is granted; if it
 * throws, access is denied. A resource that cannot record the actor must not
 * serve support requests (IMP-020).
 */
interface SupportAuditor
{
    public function recordSupportAccess(SupportEvent $event): void;
}

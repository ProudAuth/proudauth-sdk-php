<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Introspection;

/**
 * The actor-aware record a resource must persist for every support request
 * (IMP-006), allowed or denied.
 */
final class SupportEvent
{
    public const DENY_PROTECTED_OPERATION = 'protected_operation';
    public const DENY_WRITE_NOT_ALLOWLISTED = 'write_not_allowlisted';

    public function __construct(
        public readonly string $grantId,
        /** The real administrator (act.sub). */
        public readonly string $actor,
        public readonly ?string $actorIssuer,
        /** The effective customer subject. */
        public readonly string $subject,
        public readonly string $orgId,
        public readonly string $clientId,
        public readonly string $tokenId,
        public readonly string $operation,
        /** Effective classification: false when declared a write or the name carries a write verb. */
        public readonly bool $read,
        public readonly bool $allowed,
        /** Why access was denied (one of the DENY_* constants), or null when allowed. */
        public readonly ?string $denyReason,
        public readonly \DateTimeImmutable $at,
    ) {
    }
}

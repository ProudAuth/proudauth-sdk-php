<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * RFC 8693 actor claim ("act"): who is acting on behalf of the subject.
 */
final class Actor
{
    public function __construct(
        public readonly string $subject,
        public readonly ?string $issuer = null,
        public readonly ?Actor $act = null,
    ) {
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * The claims of a validated ID token.
 */
final class IdTokenClaims
{
    /**
     * @param list<string>         $audience
     * @param list<string>         $amr
     * @param array<string, mixed> $claims every verified claim, for application-specific fields
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $subject,
        public readonly array $audience,
        public readonly \DateTimeImmutable $expiry,
        public readonly ?\DateTimeImmutable $issuedAt,
        public readonly ?\DateTimeImmutable $authTime,
        public readonly ?string $nonce,
        public readonly ?string $acr,
        public readonly array $amr,
        public readonly ?string $azp,
        public readonly ?string $sid,
        public readonly ?string $atHash,
        public readonly ?string $email,
        public readonly ?string $name,
        public readonly array $claims,
    ) {
    }
}

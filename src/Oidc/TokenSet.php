<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * Tokens from the token endpoint. Keep them server-side; never send refresh
 * or ID tokens to business APIs.
 */
final class TokenSet
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        public readonly int|float $expiresIn,
        public readonly ?string $refreshToken,
        public readonly ?string $idToken,
        public readonly ?string $scope,
        /** Absolute access-token expiry, milliseconds since the epoch. */
        public readonly int|float $expiresAt,
    ) {
    }

    /** A copy with the refresh and ID tokens replaced. */
    public function with(?string $refreshToken, ?string $idToken): self
    {
        return new self($this->accessToken, $this->tokenType, $this->expiresIn, $refreshToken, $idToken, $this->scope, $this->expiresAt);
    }

    /**
     * A plain array for server-side storage.
     *
     * @return array{access_token: string, token_type: string, expires_in: int|float, refresh_token: string|null, id_token: string|null, scope: string|null, expires_at: int|float}
     */
    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
            'refresh_token' => $this->refreshToken,
            'id_token' => $this->idToken,
            'scope' => $this->scope,
            'expires_at' => $this->expiresAt,
        ];
    }

    /**
     * Restores stored tokens.
     *
     * @param array<string, mixed> $a
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $a): self
    {
        $at = $a['access_token'] ?? null;
        $tt = $a['token_type'] ?? null;
        $ei = $a['expires_in'] ?? 0;
        $ea = $a['expires_at'] ?? null;
        if (!is_string($at) || $at === '' || !is_string($tt) || !(is_int($ei) || is_float($ei)) || !(is_int($ea) || is_float($ea))) {
            throw new \InvalidArgumentException('oidc-client: stored tokens are incomplete');
        }
        $opt = static fn (string $k): ?string => isset($a[$k]) && is_string($a[$k]) && $a[$k] !== '' ? $a[$k] : null;
        return new self($at, $tt, $ei, $opt('refresh_token'), $opt('id_token'), $opt('scope'), $ea);
    }

    /** Hides the tokens from var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return [
            'accessToken' => '[REDACTED]',
            'tokenType' => $this->tokenType,
            'expiresIn' => $this->expiresIn,
            'refreshToken' => $this->refreshToken === null ? null : '[REDACTED]',
            'idToken' => $this->idToken === null ? null : '[REDACTED]',
            'scope' => $this->scope,
            'expiresAt' => $this->expiresAt,
        ];
    }
}

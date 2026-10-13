<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * The per-login state. Store it server-side (for example in the PHP session,
 * keyed by a random value in an HttpOnly cookie), never only in a
 * client-readable cookie, and use it once.
 */
final class AuthRequest
{
    /** @var list<string> */
    public readonly array $scopes;

    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public readonly string $state,
        public readonly string $nonce,
        public readonly string $codeVerifier,
        public readonly string $url,
        public readonly string $redirectUri,
        array $scopes,
        /** Milliseconds since the epoch. */
        public readonly int|float $createdAt,
    ) {
        $this->scopes = array_values($scopes);
    }

    /**
     * A plain array for server-side storage (JSON, Redis, the PHP session).
     *
     * @return array{state: string, nonce: string, code_verifier: string, url: string, redirect_uri: string, scopes: list<string>, created_at: int|float}
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'url' => $this->url,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'created_at' => $this->createdAt,
        ];
    }

    /**
     * Restores a stored login state.
     *
     * @param array<string, mixed> $a
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $a): self
    {
        foreach (['state', 'nonce', 'code_verifier', 'url', 'redirect_uri'] as $k) {
            if (!isset($a[$k]) || !is_string($a[$k]) || $a[$k] === '') {
                throw new \InvalidArgumentException("oidc-client: stored login state lacks {$k}");
            }
        }
        $scopes = $a['scopes'] ?? [];
        if (!is_array($scopes) || array_filter($scopes, 'is_string') !== $scopes) {
            throw new \InvalidArgumentException('oidc-client: stored login state has invalid scopes');
        }
        $created = $a['created_at'] ?? 0;
        return new self($a['state'], $a['nonce'], $a['code_verifier'], $a['url'], $a['redirect_uri'], array_values($scopes), is_int($created) || is_float($created) ? $created : 0);
    }

    /** Hides the state, nonce and PKCE verifier from var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return ['redirectUri' => $this->redirectUri, 'scopes' => $this->scopes, 'createdAt' => $this->createdAt, 'state' => '[REDACTED]', 'nonce' => '[REDACTED]', 'codeVerifier' => '[REDACTED]'];
    }
}

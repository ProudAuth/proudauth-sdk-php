<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * Server-side tokens for one browser session, with refresh (SES-009). Create
 * it with OidcClient::session().
 *
 * Refresh tokens rotate, and presenting one twice is reuse that revokes the
 * whole token family (SES-007/008, TEST-030). Within one Session object
 * refresh happens once: later calls use the rotated tokens. A failed refresh
 * clears the session (a lost refresh response cannot be retried safely,
 * §24.3): the user must authenticate again.
 *
 * PHP serves concurrent requests of one browser session in separate workers,
 * each with its own Session object. Serialize refreshes across them: either
 * keep the tokens in a session store that locks per session (PHP's default
 * files session handler does) and read them at the start of the request, or
 * pass `lock` (e.g. FileRefreshLock::for($sessionId)) together with `reload`,
 * which reads the stored tokens inside the lock so a worker that waited picks
 * up the tokens another worker just rotated instead of reusing the old
 * refresh token.
 */
final class Session
{
    private ?TokenSet $tokens;
    private ?IdTokenClaims $idClaims;
    private int $refreshCount = 0;

    /**
     * @internal use OidcClient::session()
     *
     * @param \Closure(array<string, string>): TokenSet    $tokenRequest
     * @param \Closure(string, string): IdTokenClaims      $validateIdToken
     * @param \Closure(): (int|float)                      $now
     * @param (\Closure(TokenSet): void)|null              $onRefresh
     * @param (\Closure(\Closure): mixed)|null             $lock
     * @param (\Closure(): ?TokenSet)|null                 $reload
     */
    public function __construct(
        private readonly \Closure $tokenRequest,
        private readonly \Closure $validateIdToken,
        private readonly \Closure $now,
        TokenSet $tokens,
        ?IdTokenClaims $idClaims,
        private readonly ?\Closure $onRefresh,
        private readonly int|float $refreshWindowMs,
        private readonly ?\Closure $lock,
        private readonly ?\Closure $reload,
    ) {
        $this->tokens = $tokens;
        $this->idClaims = $idClaims;
    }

    /** Current tokens, or null after logout or a failed refresh. */
    public function tokens(): ?TokenSet
    {
        return $this->tokens;
    }

    public function idClaims(): ?IdTokenClaims
    {
        return $this->idClaims;
    }

    /** Refresh requests made by this session (diagnostics and tests). */
    public function refreshCount(): int
    {
        return $this->refreshCount;
    }

    /** Forgets the tokens locally (does not revoke; see OidcClient::logout()). */
    public function clear(): void
    {
        $this->tokens = null;
    }

    /**
     * Returns a valid access token, refreshing once when it is about to expire.
     * Pass `$rejectedToken` when an API rejected the current access token to
     * force one refresh; a stale rejection (of a token already replaced) does
     * not refresh again.
     *
     * @throws OidcException reauthenticate when there are no tokens or the refresh failed
     */
    public function accessToken(?string $rejectedToken = null): string
    {
        $t = $this->tokens;
        if ($t === null) {
            throw new OidcException(OidcErrorCode::Reauthenticate);
        }
        if (!$this->needsRefresh($t, $rejectedToken)) {
            return $t->accessToken;
        }
        if ($this->lock === null) {
            return $this->refreshWith($t);
        }
        $result = ($this->lock)(function () use ($rejectedToken): string {
            $current = $this->tokens;
            if ($this->reload !== null) {
                $current = ($this->reload)();
                if ($current !== null && !$current instanceof TokenSet) {
                    throw new \UnexpectedValueException('oidc-client: reload must return a TokenSet or null');
                }
                $this->tokens = $current;
            }
            if ($current === null) {
                throw new OidcException(OidcErrorCode::Reauthenticate);
            }
            if (!$this->needsRefresh($current, $rejectedToken)) {
                return $current->accessToken; // another request refreshed meanwhile
            }
            return $this->refreshWith($current);
        });
        if (!is_string($result)) {
            throw new \UnexpectedValueException('oidc-client: lock must return the result of the closure it runs');
        }
        return $result;
    }

    private function needsRefresh(TokenSet $t, ?string $rejectedToken): bool
    {
        $forced = $rejectedToken !== null && $rejectedToken === $t->accessToken;
        return $forced || !((float) ($this->now)() + $this->refreshWindowMs < $t->expiresAt);
    }

    private function refreshWith(TokenSet $current): string
    {
        if ($current->refreshToken === null) {
            throw new OidcException(OidcErrorCode::Reauthenticate);
        }
        try {
            $this->refreshCount++;
            $nt = ($this->tokenRequest)(['grant_type' => 'refresh_token', 'refresh_token' => $current->refreshToken]);
            $idClaims = $this->idClaims;
            if ($nt->idToken !== null) {
                $c = ($this->validateIdToken)($nt->idToken, $nt->accessToken);
                if ($this->idClaims !== null && $c->subject !== $this->idClaims->subject) {
                    throw new OidcException(OidcErrorCode::IdToken, 'refreshed ID token subject changed');
                }
                $idClaims = $c;
            }
            $next = $nt->with($nt->refreshToken ?? $current->refreshToken, $nt->idToken ?? $current->idToken);
            $this->idClaims = $idClaims;
        } catch (\Throwable $err) {
            $this->tokens = null;
            if ($err instanceof OidcException && $err->errorCode === OidcErrorCode::Reauthenticate) {
                throw $err;
            }
            throw new OidcException(
                OidcErrorCode::Reauthenticate,
                $err instanceof OidcException ? $err->errorCode->value : 'refresh failed',
                previous: $err,
            );
        }
        $this->tokens = $next;
        if ($this->onRefresh !== null) {
            ($this->onRefresh)($next);
        }
        return $next->accessToken;
    }
}

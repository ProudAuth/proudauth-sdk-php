<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * OIDC client errors. Messages carry categories only, never tokens, codes or
 * secrets ("oidc-client: invalid ID token (at_hash)").
 */
final class OidcException extends \RuntimeException
{
    /**
     * @param string|null $reason        the failed check (e.g. "issuer", "audience", "at_hash") or provider detail
     * @param string|null $providerError the OAuth error code returned by the provider, when there is one
     * @param int|null    $status        the HTTP status from the provider, when there is one
     */
    public function __construct(
        public readonly OidcErrorCode $errorCode,
        public readonly ?string $reason = null,
        public readonly ?string $providerError = null,
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        $extra = array_filter(
            [$reason, $providerError, $status !== null ? 'HTTP ' . $status : null],
            static fn (?string $v): bool => $v !== null && $v !== '',
        );
        parent::__construct('oidc-client: ' . $errorCode->message() . ($extra !== [] ? ' (' . implode(', ', $extra) . ')' : ''), 0, $previous);
    }

    /** Type guard like the Node SDK's isOIDCError(err, code). */
    public static function matches(mixed $error, ?OidcErrorCode $code = null): bool
    {
        return $error instanceof self && ($code === null || $error->errorCode === $code);
    }
}

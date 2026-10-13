<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * Transport-level failures: timeouts, network errors, redirects, oversized or
 * unparsable responses, and token-source failures. Messages never contain
 * request bodies, query strings or credentials.
 */
final class AdminRequestException extends \RuntimeException
{
    public function __construct(
        public readonly AdminErrorCode $errorCode,
        public readonly string $method,
        /** The request path without its query string. */
        public readonly string $path,
        ?\Throwable $previous = null,
    ) {
        parent::__construct("admin: {$method} {$path} failed ({$errorCode->value})", 0, $previous);
    }
}

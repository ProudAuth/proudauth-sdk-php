<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Http;

/**
 * A transport-level failure. Messages never contain request or response
 * bodies, headers or credentials.
 */
final class TransportException extends \RuntimeException
{
    public const TIMEOUT = 'timeout';
    public const NETWORK = 'network';
    public const TOO_LARGE = 'too_large';
    public const REDIRECT = 'redirect';

    /**
     * @param string   $kind   one of the constants above
     * @param int|null $status the HTTP status, when one was received
     */
    public function __construct(
        public readonly string $kind,
        string $detail = '',
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct('transport: ' . $kind . ($detail !== '' ? ' (' . $detail . ')' : ''), 0, $previous);
    }
}

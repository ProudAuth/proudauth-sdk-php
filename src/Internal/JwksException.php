<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

/**
 * @internal
 */
final class JwksException extends \RuntimeException
{
    public const UNAVAILABLE = 'unavailable';
    public const UNKNOWN_KEY = 'unknown_key';

    public function __construct(public readonly string $reason, ?\Throwable $previous = null)
    {
        parent::__construct($reason === self::UNAVAILABLE ? 'key set unavailable' : 'unknown signing key', 0, $previous);
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Jose;

/**
 * @internal
 */
final class JwsException extends \RuntimeException
{
    public const MALFORMED = 'malformed';
    public const DUPLICATE = 'duplicate';

    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason === self::DUPLICATE ? 'duplicate JSON member' : 'malformed JWS');
    }
}

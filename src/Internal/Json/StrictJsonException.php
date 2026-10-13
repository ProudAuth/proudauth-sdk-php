<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Json;

/**
 * @internal
 */
final class StrictJsonException extends \RuntimeException
{
    public const MALFORMED = 'malformed';
    public const DUPLICATE = 'duplicate';

    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason === self::DUPLICATE ? 'duplicate JSON member name' : 'malformed JSON');
    }
}

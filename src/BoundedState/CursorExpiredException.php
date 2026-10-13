<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\BoundedState;

use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Thrown by BoundedState::sync() when the stream answers 410: the cursor is
 * older than the retained history. sync() has already rewound to the
 * beginning of the retained history (keeping every revocation it knows), so
 * the next sync() replays it; run() does so immediately. Its category is
 * `unavailable`.
 */
final class CursorExpiredException extends VerifierException
{
    public function __construct()
    {
        parent::__construct(
            VerifierErrorCode::Unavailable,
            new \RuntimeException('session-event cursor is older than the retained history (HTTP 410)'),
        );
    }
}

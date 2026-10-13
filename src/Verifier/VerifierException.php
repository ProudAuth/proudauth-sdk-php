<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

/**
 * Every verification, introspection, support-guard and bounded-state failure.
 * The category is `$errorCode`; the message is fixed per category
 * ("verifier: wrong audience") and never contains token material, secrets or
 * claim values (SDK-008). The cause, when there is one, is the previous
 * exception.
 */
class VerifierException extends \RuntimeException
{
    /**
     * @param list<string> $scopes for Scope errors: the scopes the operation requires
     */
    public function __construct(
        public readonly VerifierErrorCode $errorCode,
        ?\Throwable $previous = null,
        public readonly array $scopes = [],
    ) {
        parent::__construct('verifier: ' . $errorCode->message(), 0, $previous);
    }

    /** Reports whether this error has one of the given categories. */
    public function is(VerifierErrorCode ...$codes): bool
    {
        return in_array($this->errorCode, $codes, true);
    }

    /** Type guard like the Node SDK's isVerifierError(err, code). */
    public static function matches(mixed $error, ?VerifierErrorCode $code = null): bool
    {
        return $error instanceof self && ($code === null || $error->errorCode === $code);
    }
}

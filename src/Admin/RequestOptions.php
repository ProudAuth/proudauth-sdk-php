<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * Per-request options of the administration client.
 */
final class RequestOptions
{
    public function __construct(
        /** Idempotency key for safe retries of creates (API-005); reuse it when retrying. */
        public readonly ?string $idempotencyKey = null,
        /** Optimistic-concurrency precondition (API-010): the ETag from a previous read. */
        public readonly ?string $ifMatch = null,
        /** Deadline for this request in milliseconds (default: the client's). */
        public readonly int|float|null $timeoutMs = null,
    ) {
    }

    /** A copy with an idempotency key, keeping one that is already set. */
    public function withDefaultIdempotencyKey(string $key): self
    {
        return $this->idempotencyKey !== null && $this->idempotencyKey !== ''
            ? $this
            : new self($key, $this->ifMatch, $this->timeoutMs);
    }
}

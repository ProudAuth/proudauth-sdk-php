<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * A successful administration API response. `data` is the decoded JSON body
 * (associative arrays; null for an empty body) with one-time secrets wrapped
 * in Secret.
 */
final class AdminResponse
{
    /**
     * @param array<string, list<string>> $headers lowercase names
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        /** ETag of the returned representation, for If-Match. */
        public readonly ?string $etag,
        /** Set when the server marks the operation deprecated (API-013). */
        public readonly ?string $deprecation,
        public readonly ?string $sunset,
        public readonly mixed $data,
    ) {
    }

    /** All values of a response header joined with ", ", or null. */
    public function header(string $name): ?string
    {
        $v = $this->headers[strtolower($name)] ?? null;
        return $v === null ? null : implode(', ', $v);
    }
}

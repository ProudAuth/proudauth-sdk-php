<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Http;

/**
 * An outgoing HTTP request. Header names are lowercase.
 */
final class Request
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly array $headers = [],
        public readonly ?string $body = null,
        public readonly int $timeoutMs = 10_000,
        public readonly int $maxResponseBytes = 1 << 20,
    ) {
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** Hides header values (Authorization, cookies) and the body from var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return [
            'method' => $this->method,
            'url' => $this->url,
            'headers' => array_map(static fn (): string => '[REDACTED]', $this->headers),
            'body' => $this->body === null ? null : '[REDACTED]',
            'timeoutMs' => $this->timeoutMs,
            'maxResponseBytes' => $this->maxResponseBytes,
        ];
    }
}

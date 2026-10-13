<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Http;

/**
 * An HTTP response. Header names are lowercase; each name maps to its values
 * in the order received.
 */
final class Response
{
    /** @var array<string, list<string>> */
    public readonly array $headers;

    /**
     * @param array<string, string|list<string>> $headers
     */
    public function __construct(
        public readonly int $status,
        array $headers = [],
        public readonly string $body = '',
    ) {
        $norm = [];
        foreach ($headers as $name => $values) {
            $key = strtolower((string) $name);
            foreach ((array) $values as $v) {
                $norm[$key][] = (string) $v;
            }
        }
        $this->headers = $norm;
    }

    /** All values of a header joined with ", " (like the Fetch API's Headers.get), or null. */
    public function header(string $name): ?string
    {
        $v = $this->headers[strtolower($name)] ?? null;
        return $v === null ? null : implode(', ', $v);
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Cache;

/**
 * Keeps values in this object only (the lifetime of the PHP process or
 * request). Share one instance between verifiers to share their key sets.
 */
final class MemoryStore implements Store
{
    /** @var array<string, string> */
    private array $values = [];

    public function get(string $key): ?string
    {
        return $this->values[$key] ?? null;
    }

    public function set(string $key, string $value): void
    {
        $this->values[$key] = $value;
    }
}

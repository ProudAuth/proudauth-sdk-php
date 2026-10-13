<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Json;

/**
 * A JSON object produced by StrictJson. Objects are kept apart from JSON
 * arrays (PHP lists), so `{}` and `[]`, or `{"0":1}` and `[1]`, are never
 * confused. Member names are unique (duplicates are rejected while parsing).
 *
 * @internal
 */
final class JsonObject
{
    /**
     * @param array<array-key, mixed> $members
     */
    public function __construct(private readonly array $members = [])
    {
    }

    /** Reports whether the member exists (even when its value is null). */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->members);
    }

    /** The member's value, or null when it is missing or null. */
    public function get(string $name): mixed
    {
        return $this->members[$name] ?? null;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_map('strval', array_keys($this->members));
    }

    public function count(): int
    {
        return count($this->members);
    }

    /**
     * Converts the object to PHP arrays recursively (objects become associative
     * arrays, JSON arrays stay lists).
     *
     * @return array<array-key, mixed>
     */
    public function toArray(): array
    {
        $out = [];
        foreach ($this->members as $k => $v) {
            $out[$k] = self::toPhp($v);
        }
        return $out;
    }

    /** Converts any parsed JSON value to plain PHP values. */
    public static function toPhp(mixed $v): mixed
    {
        if ($v instanceof self) {
            return $v->toArray();
        }
        if (is_array($v)) {
            return array_map(self::toPhp(...), $v);
        }
        return $v;
    }
}

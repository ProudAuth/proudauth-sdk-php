<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

/**
 * Query strings with the semantics of the WHATWG URLSearchParams (ordered
 * name/value pairs, duplicates kept, "+" read as a space), so parameter
 * handling matches the Node SDK exactly. PHP's parse_str() is not used: it
 * drops duplicates and rewrites names ("a.b" becomes "a_b", "a[]" an array).
 *
 * @internal
 */
final class Query
{
    /** @var list<array{0: string, 1: string}> */
    private array $pairs;

    /** @param list<array{0: string, 1: string}> $pairs */
    private function __construct(array $pairs)
    {
        $this->pairs = $pairs;
    }

    public static function parse(string $query): self
    {
        if (str_starts_with($query, '?')) {
            $query = substr($query, 1);
        }
        $pairs = [];
        foreach (explode('&', $query) as $piece) {
            if ($piece === '') {
                continue;
            }
            $eq = strpos($piece, '=');
            $name = $eq === false ? $piece : substr($piece, 0, $eq);
            $value = $eq === false ? '' : substr($piece, $eq + 1);
            $pairs[] = [self::decode($name), self::decode($value)];
        }
        return new self($pairs);
    }

    /**
     * Pairs from an array; an array value adds one pair per element (so
     * duplicates survive, as in a raw query string).
     *
     * @param array<array-key, mixed> $fields
     */
    public static function fromArray(array $fields): self
    {
        $pairs = [];
        foreach ($fields as $k => $v) {
            foreach (is_array($v) ? $v : [$v] as $one) {
                $pairs[] = [(string) $k, is_bool($one) ? ($one ? 'true' : 'false') : (is_scalar($one) ? (string) $one : '')];
            }
        }
        return new self($pairs);
    }

    private static function decode(string $s): string
    {
        return rawurldecode(str_replace('+', ' ', $s));
    }

    public function has(string $name): bool
    {
        foreach ($this->pairs as [$n]) {
            if ($n === $name) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    public function getAll(string $name): array
    {
        $out = [];
        foreach ($this->pairs as [$n, $v]) {
            if ($n === $name) {
                $out[] = $v;
            }
        }
        return $out;
    }

    /** Replaces the first pair named $name and removes the others, or appends one. */
    public function set(string $name, string $value): void
    {
        $out = [];
        $done = false;
        foreach ($this->pairs as $p) {
            if ($p[0] !== $name) {
                $out[] = $p;
            } elseif (!$done) {
                $out[] = [$name, $value];
                $done = true;
            }
        }
        if (!$done) {
            $out[] = [$name, $value];
        }
        $this->pairs = $out;
    }

    /** application/x-www-form-urlencoded serialization, as URLSearchParams.toString(). */
    public function toString(): string
    {
        $parts = [];
        foreach ($this->pairs as [$n, $v]) {
            $parts[] = self::encode($n) . '=' . self::encode($v);
        }
        return implode('&', $parts);
    }

    private static function encode(string $s): string
    {
        // The WHATWG form serializer leaves * - . _ and alphanumerics, and turns spaces into "+".
        return strtr(rawurlencode($s), ['%20' => '+', '%2A' => '*', '~' => '%7E']);
    }
}

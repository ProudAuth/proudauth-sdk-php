<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Cache;

/**
 * A small key-value store that lets the key-set cache outlive one PHP request
 * (PHP-FPM and similar runtimes build every object afresh per request).
 * Values are opaque strings the SDK writes itself; an implementation only has
 * to keep them.
 *
 * Whoever can write to the store can make the SDK trust a signing key, so
 * back it with storage only the application can write: APCu, a private
 * directory (FileStore), or a Redis/Memcached instance you control.
 *
 * An APCu adapter is three lines:
 *
 *     final class ApcuStore implements Store {
 *         public function get(string $key): ?string { $v = apcu_fetch($key, $ok); return $ok && is_string($v) ? $v : null; }
 *         public function set(string $key, string $value): void { apcu_store($key, $value); }
 *     }
 */
interface Store
{
    public function get(string $key): ?string;

    public function set(string $key, string $value): void;
}

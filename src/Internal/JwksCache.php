<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

use ProudAuth\Sdk\Cache\Store;
use ProudAuth\Sdk\Internal\Jose\PublicKey;
use ProudAuth\Sdk\Internal\Json\JsonObject;
use ProudAuth\Sdk\Internal\Json\StrictJson;

/**
 * A key cache for one trusted JWKS URL with bounded refreshes (§14.4,
 * TEST-005). The URL always comes from configuration (or the configured
 * issuer's discovery document), never from a token header such as jku or x5u.
 *
 * Refresh semantics mirror the Go and Node SDKs:
 *  - the first lookup loads the key set;
 *  - an unknown kid triggers at most one refresh, and refreshes are spaced by
 *    at least the minimum refresh interval, so floods of random kids cannot
 *    cause a request storm;
 *  - a failed fetch keeps the previously known keys; a successful fetch
 *    replaces the set (retired keys disappear);
 *  - two usable keys under one kid make selection ambiguous: neither is trusted.
 *
 * PHP has no concurrent callers inside one request, so there is nothing to
 * coalesce in-process. With a Store, the key set and the refresh bookkeeping
 * (time of the last fetch, whether it failed) are shared across requests and
 * workers, so the refresh bound holds for the whole application rather than
 * per request.
 *
 * @internal
 */
final class JwksCache
{
    /** @var array<string, PublicKey> */
    private array $keys = [];
    private ?float $lastFetch = null;
    private bool $everLoaded = false;
    private bool $lastFailed = false;
    private int $fetchCount = 0;
    private ?string $document = null;
    private readonly string $storeKey;

    /**
     * @param \Closure(): (int|float) $now milliseconds since the epoch
     */
    public function __construct(
        private readonly string $url,
        private readonly HttpClient $http,
        private readonly int $timeoutMs,
        private readonly int|float $minRefreshIntervalMs,
        private readonly \Closure $now,
        private readonly ?Store $store = null,
        private readonly int $maxBytes = 1 << 20,
    ) {
        $this->storeKey = 'proudauth.jwks.v1.' . hash('sha256', $url);
    }

    /** Number of key-set fetches this instance started (diagnostics and tests). */
    public function fetchCount(): int
    {
        return $this->fetchCount;
    }

    /**
     * @throws JwksException
     */
    public function getKey(string $kid): PublicKey
    {
        $this->loadState();
        $this->refresh(false);
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        // One bounded refresh for an unknown kid.
        $this->refresh(true);
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        if (!$this->everLoaded && $this->lastFailed) {
            throw new JwksException(JwksException::UNAVAILABLE);
        }
        throw new JwksException(JwksException::UNKNOWN_KEY);
    }

    private function refresh(bool $force): void
    {
        if (!$force && $this->keys !== []) {
            return;
        }
        $now = (float) ($this->now)();
        if ($this->lastFetch !== null && $now - $this->lastFetch < $this->minRefreshIntervalMs) {
            return;
        }
        $this->lastFetch = $now;
        $this->fetchCount++;
        $this->load();
    }

    private function load(): void
    {
        try {
            $res = $this->http->send('GET', $this->url, ['accept' => 'application/jwk-set+json, application/json'], null, $this->timeoutMs, $this->maxBytes);
            if ($res->status !== 200) {
                throw new \RuntimeException('key set endpoint returned HTTP ' . $res->status);
            }
            $this->keys = self::parse($res->body);
            $this->document = $res->body;
            $this->everLoaded = true;
            $this->lastFailed = false;
        } catch (\Exception $cause) {
            $this->lastFailed = true;
            $this->saveState();
            throw new JwksException(JwksException::UNAVAILABLE, $cause);
        }
        $this->saveState();
    }

    /**
     * @return array<string, PublicKey>
     *
     * @throws \RuntimeException when the document is not a key set
     */
    private static function parse(string $document): array
    {
        $set = StrictJson::decode($document);
        if (!$set instanceof JsonObject || !is_array($set->get('keys'))) {
            throw new \RuntimeException('key set has no keys array');
        }
        $keys = [];
        $ambiguous = [];
        foreach ($set->get('keys') as $jwk) {
            $k = PublicKey::fromJwk($jwk);
            if ($k === null) {
                continue;
            }
            if (isset($keys[$k->kid])) {
                $ambiguous[$k->kid] = true;
            } else {
                $keys[$k->kid] = $k;
            }
        }
        // Two usable keys under one kid make key selection ambiguous (TEST-004): trust neither.
        return array_diff_key($keys, $ambiguous);
    }

    private function loadState(): void
    {
        if ($this->store === null) {
            return;
        }
        $raw = $this->store->get($this->storeKey);
        if ($raw === null) {
            return;
        }
        $state = json_decode($raw, true);
        if (!is_array($state) || ($state['url'] ?? null) !== $this->url) {
            return;
        }
        $doc = $state['document'] ?? null;
        if (is_string($doc) && $doc !== $this->document) {
            try {
                $this->keys = self::parse($doc);
                $this->document = $doc;
                $this->everLoaded = true;
            } catch (\Exception) {
                // An unreadable stored document is ignored; the next fetch replaces it.
            }
        }
        $last = $state['lastFetch'] ?? null;
        if ((is_int($last) || is_float($last)) && ($this->lastFetch === null || $last > $this->lastFetch)) {
            $this->lastFetch = (float) $last;
        }
        $this->lastFailed = ($state['lastFailed'] ?? false) === true;
    }

    private function saveState(): void
    {
        if ($this->store === null) {
            return;
        }
        $state = json_encode([
            'url' => $this->url,
            'document' => $this->document,
            'lastFetch' => $this->lastFetch,
            'lastFailed' => $this->lastFailed,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($state === false) {
            return;
        }
        try {
            $this->store->set($this->storeKey, $state);
        } catch (\Exception) {
            // A cache that cannot be written only costs extra fetches.
        }
    }
}

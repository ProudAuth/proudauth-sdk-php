<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

/**
 * A strictly parsed absolute http(s) URL. Validated URLs are re-serialized
 * from their parsed parts before use, so a URL that this parser and the HTTP
 * client would read differently never reaches the network. Anything unusual
 * (whitespace, control or non-ASCII characters, backslashes, percent-encoded
 * or empty hosts, user information) is refused.
 *
 * @internal
 */
final class Url
{
    public const NOT_ABSOLUTE = 'absolute';
    public const NOT_HTTP = 'http';
    public const CREDENTIALS = 'credentials';

    private function __construct(
        public readonly string $scheme,
        public readonly string $host,
        public readonly ?int $port,
        public readonly string $path,
        public readonly ?string $query,
        public readonly ?string $fragment,
    ) {
    }

    /**
     * @throws \UnexpectedValueException with one of the NOT_ABSOLUTE, NOT_HTTP or CREDENTIALS messages
     */
    public static function parse(string $s): self
    {
        if ($s === '' || preg_match('/^[\x21-\x7e]+$/D', $s) !== 1 || str_contains($s, '\\')) {
            throw new \UnexpectedValueException(self::NOT_ABSOLUTE);
        }
        if (preg_match('/^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$/sD', $s, $m) !== 1) {
            throw new \UnexpectedValueException(self::NOT_ABSOLUTE);
        }
        $scheme = strtolower($m[1]);
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new \UnexpectedValueException(self::NOT_HTTP);
        }
        $rest = $m[2];
        if (!str_starts_with($rest, '//')) {
            throw new \UnexpectedValueException(self::NOT_ABSOLUTE);
        }
        $rest = substr($rest, 2);
        $end = strcspn($rest, '/?#');
        $authority = substr($rest, 0, $end);
        $rest = substr($rest, $end);
        if (str_contains($authority, '@')) {
            throw new \UnexpectedValueException(self::CREDENTIALS);
        }
        if (preg_match('/^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._\-]+)(?::([0-9]*))?$/D', $authority, $a) !== 1) {
            throw new \UnexpectedValueException(self::NOT_ABSOLUTE);
        }
        $host = strtolower($a[1]);
        if ($host[0] === '[' && strlen((string) inet_pton(substr($host, 1, -1))) !== 16) {
            throw new \UnexpectedValueException(self::NOT_ABSOLUTE);
        }
        $port = null;
        if (isset($a[2]) && $a[2] !== '') {
            if (strlen($a[2]) > 5 || (int) $a[2] > 65535) {
                throw new \UnexpectedValueException(self::NOT_ABSOLUTE);
            }
            $port = (int) $a[2];
            if ($port === ($scheme === 'https' ? 443 : 80)) {
                $port = null;
            }
        }
        $fragment = null;
        $hash = strpos($rest, '#');
        if ($hash !== false) {
            $fragment = substr($rest, $hash + 1);
            $rest = substr($rest, 0, $hash);
        }
        $query = null;
        $q = strpos($rest, '?');
        if ($q !== false) {
            $query = substr($rest, $q + 1);
            $rest = substr($rest, 0, $q);
        }
        $path = $rest === '' ? '/' : $rest;
        return new self($scheme, $host, $port, $path, $query, $fragment);
    }

    /** scheme://host[:port], with the default port omitted. */
    public function origin(): string
    {
        return $this->scheme . '://' . $this->host . ($this->port !== null ? ':' . $this->port : '');
    }

    public function withQuery(?string $query): self
    {
        return new self($this->scheme, $this->host, $this->port, $this->path, $query, $this->fragment);
    }

    public function toString(): string
    {
        return $this->origin() . $this->path
            . ($this->query !== null ? '?' . $this->query : '')
            . ($this->fragment !== null ? '#' . $this->fragment : '');
    }

    /**
     * Validates a configured URL like the Node SDK's requireHttpUrl and
     * returns it normalized.
     *
     * @throws \InvalidArgumentException
     */
    public static function requireHttp(mixed $value, string $what, string $prefix): self
    {
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException("{$prefix}: {$what} is required");
        }
        try {
            return self::parse($value);
        } catch (\UnexpectedValueException $e) {
            throw new \InvalidArgumentException(match ($e->getMessage()) {
                self::NOT_HTTP => "{$prefix}: {$what} must be an http(s) URL",
                self::CREDENTIALS => "{$prefix}: {$what} must not contain credentials",
                default => "{$prefix}: {$what} must be an absolute URL",
            });
        }
    }
}

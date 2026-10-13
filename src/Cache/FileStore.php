<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Cache;

/**
 * Keeps values as files in one directory, shared by every PHP worker on the
 * host. Files are written with mode 0600 and replaced atomically (write to a
 * temporary file, then rename), so readers never see partial values.
 *
 * Use a directory that only the application's user can write: anyone who can
 * write there can make the SDK trust a signing key.
 */
final class FileStore implements Store
{
    private readonly string $directory;

    public function __construct(string $directory)
    {
        if ($directory === '' || !is_dir($directory)) {
            throw new \InvalidArgumentException('cache: directory does not exist');
        }
        $this->directory = rtrim($directory, '/\\');
    }

    private function path(string $key): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . 'proudauth-' . hash('sha256', $key) . '.cache';
    }

    public function get(string $key): ?string
    {
        $path = $this->path($key);
        if (!is_file($path)) {
            return null;
        }
        $v = @file_get_contents($path);
        return is_string($v) ? $v : null;
    }

    public function set(string $key, string $value): void
    {
        $tmp = @tempnam($this->directory, 'proudauth-');
        if ($tmp === false) {
            throw new \RuntimeException('cache: cannot create a file in the cache directory');
        }
        try {
            if (@file_put_contents($tmp, $value) !== strlen($value) || !@chmod($tmp, 0600) || !@rename($tmp, $this->path($key))) {
                throw new \RuntimeException('cache: cannot write the cache file');
            }
        } finally {
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        }
    }
}

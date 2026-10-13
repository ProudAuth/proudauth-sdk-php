<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * An exclusive lock per browser session based on flock(), for serializing
 * token refreshes between PHP workers on one host:
 *
 *     $locks = new FileRefreshLock('/var/lib/myapp/locks');
 *     $session = $oidc->session($tokens, lock: $locks->for($sessionId), reload: fn () => loadTokens($sessionId));
 *
 * Several hosts need a distributed lock instead (any closure with the same
 * contract works as `lock`).
 */
final class FileRefreshLock
{
    private readonly string $directory;

    public function __construct(string $directory)
    {
        if ($directory === '' || !is_dir($directory)) {
            throw new \InvalidArgumentException('oidc-client: lock directory does not exist');
        }
        $this->directory = rtrim($directory, '/\\');
    }

    /**
     * Runs $critical while holding the lock for $key and returns its result.
     *
     * @template T
     *
     * @param \Closure(): T $critical
     *
     * @return T
     */
    public function synchronized(string $key, \Closure $critical): mixed
    {
        $path = $this->directory . DIRECTORY_SEPARATOR . 'proudauth-refresh-' . hash('sha256', $key) . '.lock';
        $fh = @fopen($path, 'c');
        if ($fh === false) {
            throw new \RuntimeException('oidc-client: cannot open the refresh lock file');
        }
        try {
            @chmod($path, 0600);
            if (!flock($fh, LOCK_EX)) {
                throw new \RuntimeException('oidc-client: cannot acquire the refresh lock');
            }
            try {
                return $critical();
            } finally {
                flock($fh, LOCK_UN);
            }
        } finally {
            fclose($fh);
        }
    }

    /**
     * The lock for one browser session, in the form OidcClient::session() expects.
     *
     * @return \Closure(\Closure): mixed
     */
    public function for(string $key): \Closure
    {
        return fn (\Closure $critical): mixed => $this->synchronized($key, $critical);
    }
}

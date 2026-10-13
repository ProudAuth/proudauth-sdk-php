<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests\Support;

/**
 * Runs PHP's built-in web server (php -S) on 127.0.0.1 with a router script,
 * for tests that need a real socket.
 */
final class PhpServer
{
    /** @param resource $process */
    private function __construct(private $process, public readonly string $url)
    {
    }

    /** @param array<string, string> $env */
    public static function start(string $router, array $env = []): self
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($probe === false) {
            throw new \RuntimeException("cannot reserve a port: {$errstr}");
        }
        $name = (string) stream_socket_get_name($probe, false);
        fclose($probe);
        $port = (int) substr($name, strrpos($name, ':') + 1);
        $null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
        $process = proc_open(
            [PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=0', '-d', 'log_errors=0', '-S', "127.0.0.1:{$port}", $router],
            [0 => ['pipe', 'r'], 1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']],
            $pipes,
            dirname($router),
            $env + getenv(),
        );
        if (!is_resource($process)) {
            throw new \RuntimeException('cannot start php -S');
        }
        fclose($pipes[0]);
        $server = new self($process, "http://127.0.0.1:{$port}");
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            $c = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if ($c !== false) {
                fclose($c);
                return $server;
            }
            usleep(50_000);
        }
        $server->stop();
        throw new \RuntimeException('php -S did not start');
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests\Support;

use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Http\TransportException;

/**
 * An in-process transport: a closure answers each request. It records the
 * requests and enforces the body limit like a real transport.
 */
final class FakeTransport implements Transport
{
    /** @var list<Request> */
    public array $requests = [];

    /**
     * @param \Closure(Request): Response $handler may throw TransportException to simulate failures
     */
    public function __construct(private \Closure $handler)
    {
    }

    public function send(Request $request): Response
    {
        $this->requests[] = $request;
        $res = ($this->handler)($request);
        if (strlen($res->body) > $request->maxResponseBytes) {
            throw new TransportException(TransportException::TOO_LARGE, 'response body exceeds the configured limit', $res->status);
        }
        return $res;
    }

    public function hits(): int
    {
        return count($this->requests);
    }

    public function last(): Request
    {
        $r = end($this->requests);
        if ($r === false) {
            throw new \LogicException('no request was sent');
        }
        return $r;
    }

    /** A JSON response; a string body is sent as is. */
    public static function json(int $status, mixed $body, array $headers = []): Response
    {
        $text = is_string($body) ? $body : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        return new Response($status, $headers + ['content-type' => 'application/json'], $text);
    }

    /** Parses a form-encoded request body like URLSearchParams (first value per name). */
    public static function form(?string $body): array
    {
        $out = [];
        foreach (explode('&', (string) $body) as $piece) {
            if ($piece === '') {
                continue;
            }
            [$k, $v] = array_pad(explode('=', $piece, 2), 2, '');
            $k = urldecode($k);
            if (!array_key_exists($k, $out)) {
                $out[$k] = urldecode($v);
            }
        }
        return $out;
    }
}

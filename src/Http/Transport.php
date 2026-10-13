<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Http;

/**
 * Sends one HTTP request. The SDK's only network dependency, so tests and
 * applications can substitute their own (a proxy-aware client, a PSR-18
 * adapter, an in-process fake).
 *
 * Contract for implementations:
 *  - never follow redirects (the SDK treats 301, 302, 303, 307 and 308 as
 *    transport failures, because requests carry credentials);
 *  - enforce Request::$timeoutMs for the whole exchange and throw
 *    TransportException::TIMEOUT when it elapses;
 *  - stop reading once the body exceeds Request::$maxResponseBytes and throw
 *    TransportException::TOO_LARGE;
 *  - throw TransportException::NETWORK for every other failure;
 *  - never log request or response bodies or headers (they carry tokens
 *    and client secrets).
 */
interface Transport
{
    /**
     * @throws TransportException
     */
    public function send(Request $request): Response;
}

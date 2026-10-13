<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Http;

/**
 * The default transport, built on ext-curl. It never follows redirects,
 * speaks only HTTP and HTTPS, verifies TLS certificates and host names,
 * enforces the request deadline (connect included) and stops reading a body
 * that exceeds the request's limit (a declared Content-Length beyond the limit
 * is refused before the body is read).
 *
 * One curl handle is kept per instance so connections are reused.
 */
final class CurlTransport implements Transport
{
    private ?\CurlHandle $handle = null;

    /**
     * @param array<int, mixed> $curlOptions extra curl options, e.g. CURLOPT_CAINFO or CURLOPT_PROXY.
     *                                       They cannot re-enable redirects, other protocols or
     *                                       weaker TLS verification.
     */
    public function __construct(private readonly array $curlOptions = [])
    {
        if (!extension_loaded('curl')) {
            throw new \LogicException('proudauth: ext-curl is required for CurlTransport');
        }
    }

    public function send(Request $request): Response
    {
        if ($this->handle === null) {
            $h = curl_init();
            if ($h === false) {
                throw new TransportException(TransportException::NETWORK, 'curl_init failed');
            }
            $this->handle = $h;
        }
        $h = $this->handle;
        curl_reset($h);

        $limit = $request->maxResponseBytes;
        $body = '';
        $headers = [];
        $status = null;
        $tooLarge = false;

        // An RFC 9110 method token; anything else could smuggle a request line.
        if (preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z\-]+$/D', $request->method) !== 1) {
            throw new TransportException(TransportException::NETWORK, 'invalid method');
        }
        $headerLines = ['Expect:'];
        foreach ($request->headers as $name => $value) {
            if (preg_match('/[\r\n\0]/', $name . $value) === 1 || preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z\-]+$/D', $name) !== 1) {
                throw new TransportException(TransportException::NETWORK, 'invalid header');
            }
            $headerLines[] = $name . ': ' . $value;
        }

        $timeout = max(1, $request->timeoutMs);
        $options = [
            CURLOPT_URL => $request->url,
            CURLOPT_CUSTOMREQUEST => $request->method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_TIMEOUT_MS => $timeout,
            CURLOPT_CONNECTTIMEOUT_MS => $timeout,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headers, &$status, &$tooLarge, $limit): int {
                $len = strlen($line);
                $t = trim($line);
                if (preg_match('#^HTTP/\S+\s+([0-9]{3})#', $t, $m) === 1) {
                    // A new response (after 100 Continue): start over.
                    $status = (int) $m[1];
                    $headers = [];
                    return $len;
                }
                $colon = strpos($t, ':');
                if ($t === '' || $colon === false) {
                    return $len;
                }
                $name = strtolower(trim(substr($t, 0, $colon)));
                $value = trim(substr($t, $colon + 1));
                $headers[$name][] = $value;
                if ($name === 'content-length' && $status !== null && $status >= 200
                    && preg_match('/^[0-9]+$/D', $value) === 1 && (strlen($value) > 18 || (int) $value > $limit)) {
                    $tooLarge = true;
                    return 0; // aborts the transfer
                }
                return $len;
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$tooLarge, $limit): int {
                if (strlen($body) + strlen($chunk) > $limit) {
                    $tooLarge = true;
                    return 0; // aborts the transfer
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ];
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $options[constant('CURLOPT_PROTOCOLS_STR')] = 'http,https';
            $options[constant('CURLOPT_REDIR_PROTOCOLS_STR')] = 'http,https';
        } else {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
            $options[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        if ($request->body !== null) {
            $options[CURLOPT_POSTFIELDS] = $request->body;
        }
        if (strtoupper($request->method) === 'HEAD') {
            $options[CURLOPT_NOBODY] = true;
        }

        if ($this->curlOptions !== [] && !curl_setopt_array($h, $this->curlOptions)) {
            throw new TransportException(TransportException::NETWORK, 'invalid curl option');
        }
        if (!curl_setopt_array($h, $options)) {
            throw new TransportException(TransportException::NETWORK, 'invalid request');
        }

        $ok = curl_exec($h);
        $errno = curl_errno($h);
        $code = (int) curl_getinfo($h, CURLINFO_RESPONSE_CODE);
        curl_reset($h); // releases the callbacks (and the body they hold); connections stay cached
        if ($tooLarge) {
            throw new TransportException(TransportException::TOO_LARGE, 'response body exceeds the configured limit', $status);
        }
        if ($ok === false || $errno !== 0) {
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw new TransportException(TransportException::TIMEOUT, 'deadline exceeded', $status);
            }
            throw new TransportException(TransportException::NETWORK, 'curl error ' . $errno . ': ' . curl_strerror($errno), $status);
        }
        return new Response($code, $headers, $body);
    }
}

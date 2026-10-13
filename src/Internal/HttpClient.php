<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

use ProudAuth\Sdk\Http\CurlTransport;
use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Http\TransportException;

/**
 * Small HTTP helpers shared by the SDK modules. Nothing here logs, and no
 * helper includes request or response bodies in errors (SDK-008).
 *
 * @internal
 */
final class HttpClient
{
    private const REDIRECTS = [301, 302, 303, 307, 308];

    private readonly Transport $transport;

    public function __construct(?Transport $transport = null)
    {
        $this->transport = $transport ?? new CurlTransport();
    }

    /**
     * Sends a request. Redirects are refused (requests carry credentials) and
     * the body limit is re-checked, so a custom transport cannot weaken either.
     *
     * @param array<string, string> $headers lowercase names
     *
     * @throws TransportException
     */
    public function send(string $method, string $url, array $headers, ?string $body, int $timeoutMs, int $maxBytes): Response
    {
        $res = $this->transport->send(new Request($method, $url, $headers, $body, $timeoutMs, $maxBytes));
        if (in_array($res->status, self::REDIRECTS, true)) {
            throw new TransportException(TransportException::REDIRECT, 'redirects are not followed', $res->status);
        }
        if (strlen($res->body) > $maxBytes) {
            throw new TransportException(TransportException::TOO_LARGE, 'response body exceeds the configured limit', $res->status);
        }
        return $res;
    }

    /**
     * application/x-www-form-urlencoded encoding of one value, equivalent to
     * Go's url.QueryEscape (RFC 6749 §2.3.1 requires it for client credentials
     * in Basic auth).
     */
    public static function formEncode(string $value): string
    {
        return str_replace('%20', '+', rawurlencode($value));
    }

    /**
     * Encodes a form body; null values are left out.
     *
     * @param array<string, string|null> $fields
     */
    public static function formBody(array $fields): string
    {
        $parts = [];
        foreach ($fields as $k => $v) {
            if ($v !== null) {
                $parts[] = self::formEncode((string) $k) . '=' . self::formEncode($v);
            }
        }
        return implode('&', $parts);
    }

    /** client_secret_basic Authorization header value (RFC 6749 §2.3.1). */
    public static function basicAuthorization(string $clientId, string $clientSecret): string
    {
        return 'Basic ' . base64_encode(self::formEncode($clientId) . ':' . self::formEncode($clientSecret));
    }

    /** JavaScript's encodeURIComponent (leaves A-Z a-z 0-9 - _ . ! ~ * ' ( ) unescaped). */
    public static function encodeUriComponent(string $value): string
    {
        return strtr(rawurlencode($value), ['%21' => '!', '%2A' => '*', '%27' => "'", '%28' => '(', '%29' => ')']);
    }

    /** True when the string is valid UTF-8. */
    public static function isUtf8(string $s): bool
    {
        return preg_match('//u', $s) === 1;
    }
}

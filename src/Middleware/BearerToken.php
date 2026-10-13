<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Middleware;

use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Extracts RFC 6750 bearer tokens. Tokens are accepted from the Authorization
 * header only; a request whose query string carries `access_token` is refused
 * (TOK-023), even when a header is present too.
 */
final class BearerToken
{
    /** RFC 6750 §2.1 b64token. */
    private const B64TOKEN = '/^[A-Za-z0-9\-._~+\/]+=*$/D';

    /**
     * Extracts the token from an Authorization header value.
     *
     * @param string|list<string>|null $authorization the header value; a list holds every Authorization
     *                                                header of the request (as PSR-7's getHeader() returns
     *                                                it): empty means none, more than one is refused
     * @param string|null              $requestUri    the request target (path and query), checked for access_token
     *
     * @throws VerifierException missing_token, invalid_request or malformed
     */
    public static function fromHeader(string|array|null $authorization, ?string $requestUri = null): string
    {
        if ($requestUri !== null) {
            $q = strpos($requestUri, '?');
            if ($q !== false) {
                $query = explode('#', substr($requestUri, $q + 1), 2)[0];
                if (Query::parse($query)->has('access_token')) {
                    throw new VerifierException(VerifierErrorCode::InvalidRequest);
                }
            }
        }
        $h = $authorization;
        if ($h === []) {
            $h = null; // no Authorization header
        }
        if (is_array($h)) {
            if (count($h) !== 1) {
                throw new VerifierException(VerifierErrorCode::InvalidRequest);
            }
            $h = reset($h);
        }
        if (!is_string($h) || strlen($h) <= 7 || strtolower(substr($h, 0, 7)) !== 'bearer ') {
            throw new VerifierException(VerifierErrorCode::MissingToken);
        }
        $token = self::trim(substr($h, 7));
        if ($token === '') {
            throw new VerifierException(VerifierErrorCode::MissingToken);
        }
        if (preg_match(self::B64TOKEN, $token) !== 1) {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        return $token;
    }

    /**
     * Extracts the token from PHP's request superglobals: the Authorization
     * header from $_SERVER['HTTP_AUTHORIZATION'] (or REDIRECT_HTTP_AUTHORIZATION,
     * which Apache uses after internal rewrites) and the query string from
     * $_SERVER['REQUEST_URI'] (or QUERY_STRING).
     *
     * @param array<string, mixed>|null $server default $_SERVER
     *
     * @throws VerifierException
     */
    public static function fromGlobals(?array $server = null): string
    {
        $server ??= $_SERVER;
        $auth = $server['HTTP_AUTHORIZATION'] ?? $server['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
        $uri = $server['REQUEST_URI'] ?? null;
        if (!is_string($uri)) {
            $qs = $server['QUERY_STRING'] ?? null;
            $uri = is_string($qs) && $qs !== '' ? '?' . $qs : null;
        }
        return self::fromHeader(is_string($auth) ? $auth : null, $uri);
    }

    /** JavaScript String.prototype.trim() on the header remainder (ASCII whitespace in practice). */
    private static function trim(string $s): string
    {
        return trim($s, " \t\n\r\v\f");
    }
}

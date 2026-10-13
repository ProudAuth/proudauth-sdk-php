<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Middleware;

use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * An RFC 6750 error response for a failed request:
 *
 *  - missing token: 401 without an error code;
 *  - token in the query string: 400 invalid_request;
 *  - scope or organization: 403 insufficient_scope;
 *  - support policy: 403;
 *  - dependency unavailable or stale bounded state: 503 (fail closed, never a downgrade);
 *  - contract (misconfiguration): 500;
 *  - any other verification failure: 401 invalid_token;
 *  - anything that is not a VerifierException: 500.
 */
final class Challenge
{
    private const STATUS_TEXT = [
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        500 => 'Internal Server Error',
        503 => 'Service Unavailable',
    ];

    /**
     * @param array<string, string> $headers lowercase names (www-authenticate when one applies)
     * @param string|null           $error   the RFC 6750 error code, when one applies
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers = [],
        public readonly ?string $error = null,
    ) {
    }

    /**
     * Maps an error to its challenge.
     *
     * @param string|null  $realm  optional realm for the WWW-Authenticate challenge
     * @param list<string> $scopes scopes to advertise with insufficient_scope (default: those carried by the
     *                             exception from Claims::requireScope())
     */
    public static function fromThrowable(\Throwable $err, ?string $realm = null, array $scopes = []): self
    {
        $params = [];
        if ($realm !== null && $realm !== '') {
            $params[] = 'realm=' . self::quote($realm);
        }
        $bearer = static function (array $extra = []) use ($params): string {
            $all = [...$params, ...$extra];
            return $all !== [] ? 'Bearer ' . implode(', ', $all) : 'Bearer';
        };
        if (!$err instanceof VerifierException) {
            return new self(500);
        }
        switch ($err->errorCode) {
            case VerifierErrorCode::MissingToken:
                return new self(401, ['www-authenticate' => $bearer()]);
            case VerifierErrorCode::InvalidRequest:
                return new self(400, ['www-authenticate' => $bearer(['error="invalid_request"'])], 'invalid_request');
            case VerifierErrorCode::Scope:
                $extra = ['error="insufficient_scope"'];
                $scopes = $scopes !== [] ? $scopes : $err->scopes;
                if ($scopes !== []) {
                    $extra[] = 'scope=' . self::quote(implode(' ', $scopes));
                }
                return new self(403, ['www-authenticate' => $bearer($extra)], 'insufficient_scope');
            case VerifierErrorCode::Organization:
                // The token lacks the organization the resource needs (same as the Go and Node SDKs).
                return new self(403, ['www-authenticate' => $bearer(['error="insufficient_scope"'])], 'insufficient_scope');
            case VerifierErrorCode::SupportPolicy:
                return new self(403);
            case VerifierErrorCode::Unavailable:
            case VerifierErrorCode::StaleState:
                return new self(503);
            case VerifierErrorCode::Contract:
                return new self(500);
            default:
                return new self(401, ['www-authenticate' => $bearer(['error="invalid_token"'])], 'invalid_token');
        }
    }

    private static function quote(string $v): string
    {
        return '"' . str_replace(["\r", "\n"], ' ', addcslashes($v, '\\"')) . '"';
    }

    /** The plain-text body: the status text, never token material. */
    public function body(): string
    {
        return self::STATUS_TEXT[$this->status] ?? 'Error';
    }

    /**
     * Every response header to send: the challenge plus `cache-control: no-store`
     * and `content-type: text/plain; charset=utf-8`.
     *
     * @return array<string, string>
     */
    public function responseHeaders(): array
    {
        return $this->headers + ['cache-control' => 'no-store', 'content-type' => 'text/plain; charset=utf-8'];
    }

    /**
     * Writes the response with PHP's header() and echo. Does nothing when
     * headers were already sent.
     */
    public function send(): void
    {
        if (headers_sent()) {
            return;
        }
        foreach ($this->responseHeaders() as $name => $value) {
            header($name . ': ' . $value);
        }
        // Last: PHP turns any response that sends WWW-Authenticate into a 401,
        // which would otherwise replace 400 and 403.
        http_response_code($this->status);
        echo $this->body();
    }
}

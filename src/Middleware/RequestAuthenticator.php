<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Middleware;

use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Framework-neutral request authentication (SDK-011), the PHP counterpart of
 * the Node SDK's middleware, protect and requireScopes helpers. Every security
 * decision stays in the Authenticator (Verifier, MultiIssuerVerifier,
 * Introspector, BoundedVerifier, SupportGuard::route()); this class only
 * extracts the bearer token, calls it and translates errors into RFC 6750
 * responses. It denies by default: a handler only runs with verified claims.
 *
 * Wrapping it in a PSR-15 middleware or a framework guard takes a few lines;
 * see the README.
 */
final class RequestAuthenticator
{
    /**
     * @param string|null                                        $realm          optional realm for WWW-Authenticate
     * @param (\Closure(\Throwable): void)|null                  $onError        called with every authentication failure before
     *                                                                           the challenge is sent (telemetry; categories only)
     * @param (\Closure(\Throwable): void)|null                  $onHandlerError protect() only: called when the handler throws
     *                                                                           something other than a VerifierException
     * @param (\Closure(int, array<string, string>, string): void)|null $emit    writes a response (status, headers, body);
     *                                                                           default PHP's header() and echo
     */
    public function __construct(
        private readonly Authenticator $authenticator,
        private readonly ?string $realm = null,
        private readonly ?\Closure $onError = null,
        private readonly ?\Closure $onHandlerError = null,
        private readonly ?\Closure $emit = null,
    ) {
    }

    /**
     * Extracts the bearer token from an Authorization header value (and
     * refuses one in the query string) and authenticates it.
     *
     * @param string|list<string>|null $authorization
     *
     * @throws VerifierException
     */
    public function authenticate(string|array|null $authorization, ?string $requestUri = null): Claims
    {
        return $this->authenticator->authenticate(BearerToken::fromHeader($authorization, $requestUri));
    }

    /**
     * Authenticates the current request from PHP's superglobals.
     *
     * @param array<string, mixed>|null $server default $_SERVER
     *
     * @throws VerifierException
     */
    public function authenticateGlobals(?array $server = null): Claims
    {
        return $this->authenticator->authenticate(BearerToken::fromGlobals($server));
    }

    /**
     * The RFC 6750 response for an error.
     *
     * @param list<string> $scopes scopes to advertise with insufficient_scope
     */
    public function challenge(\Throwable $error, array $scopes = []): Challenge
    {
        return Challenge::fromThrowable($error, $this->realm, $scopes);
    }

    /**
     * Requires scopes on already-verified claims (403 insufficient_scope).
     *
     * @throws VerifierException
     */
    public static function requireScopes(Claims $claims, string ...$scopes): void
    {
        $claims->requireScope(...$scopes);
    }

    /**
     * Runs a plain-PHP handler for the current request (superglobals) only with
     * verified claims. On failure the RFC 6750 response is written, the
     * handler is skipped and null is returned.
     *
     * A VerifierException thrown by the handler (for example from
     * `$claims->requireScope()` or `$claims->requireOrganization()`) is
     * answered with its challenge (403, 503, ...). Any other exception is
     * reported to onHandlerError and answered with 500.
     *
     * @template T
     *
     * @param \Closure(Claims): T       $handler
     * @param array<string, mixed>|null $server default $_SERVER
     *
     * @return T|null
     */
    public function protect(\Closure $handler, ?array $server = null): mixed
    {
        try {
            $claims = $this->authenticateGlobals($server);
        } catch (\Throwable $err) {
            $this->report($err);
            $this->respond($this->challenge($err));
            return null;
        }
        try {
            return $handler($claims);
        } catch (VerifierException $err) {
            $this->report($err);
            $this->respond($this->challenge($err));
            return null;
        } catch (\Throwable $err) {
            if ($this->onHandlerError !== null) {
                try {
                    ($this->onHandlerError)($err);
                } catch (\Throwable) {
                    // Reporting must not change the response.
                }
            }
            $this->respond(new Challenge(500));
            return null;
        }
    }

    /** Writes a challenge response (plain-text body, no token material, no-store). */
    public function respond(Challenge $challenge): void
    {
        if ($this->emit !== null) {
            ($this->emit)($challenge->status, $challenge->responseHeaders(), $challenge->body());
            return;
        }
        $challenge->send();
    }

    private function report(\Throwable $err): void
    {
        if ($this->onError === null) {
            return;
        }
        try {
            ($this->onError)($err);
        } catch (\Throwable) {
            // Telemetry must not change the authorization outcome.
        }
    }
}

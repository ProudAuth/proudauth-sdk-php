<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

use ProudAuth\Sdk\Cache\Store;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Http\TransportException;
use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Internal\Jose\Jws;
use ProudAuth\Sdk\Internal\Jose\JwsException;
use ProudAuth\Sdk\Internal\Jose\Signature;
use ProudAuth\Sdk\Internal\Json\JsonObject;
use ProudAuth\Sdk\Internal\Json\StrictJson;
use ProudAuth\Sdk\Internal\JwksCache;
use ProudAuth\Sdk\Internal\JwksException;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Internal\Time;
use ProudAuth\Sdk\Internal\Url;

/**
 * Confidential-client helper for backends-for-frontends (SDK-004), a port of
 * the Node SDK's oidc-client and the Go SDK's oidcclient: authorization code
 * + PKCE S256, state and nonce handling, RFC 9207 issuer checks, strict
 * ID-token validation (OIDC-016), server-side token storage with refresh
 * (SES-009), revocation and RP-initiated logout.
 *
 * The issuer is trusted configuration. Discovery is fetched only from it,
 * every advertised endpoint must share the issuer's origin, and keys are
 * resolved only from the advertised jwks_uri (never from a token header).
 */
final class OidcClient
{
    private const RESERVED_AUTH_PARAMS = [
        'client_id', 'redirect_uri', 'response_type', 'state', 'nonce', 'code_challenge',
        'code_challenge_method', 'scope', 'resource', 'request', 'request_uri',
    ];

    public readonly string $issuer;
    public readonly string $clientId;

    private readonly string $issuerOrigin;
    private readonly ?string $clientSecret;
    private readonly string $redirectUri;
    /** @var list<string> */
    private readonly array $scopes;
    private readonly ?string $resource;
    /** @var array<string, true> */
    private readonly array $algorithms;
    private readonly int|float $skewMs;
    private readonly int $timeoutMs;
    private readonly int|float $minRefreshMs;
    private readonly HttpClient $http;
    /** @var \Closure(): (int|float) */
    private readonly \Closure $now;
    private ?JsonObject $meta = null;
    private ?JwksCache $jwks = null;

    /**
     * @param string|null                    $clientSecret             omit for public clients (client_id is then sent in the body)
     * @param list<string>|null              $scopes                   default ["openid"]
     * @param string|null                    $resource                 RFC 8707 resource indicator requested by default
     * @param list<string>|null              $algorithms               ID-token algorithm allowlist; default RS256, PS256, ES256, EdDSA
     * @param int|float                      $clockSkewMs              ID-token clock tolerance (default 30 000, at most 60 000)
     * @param int|float                      $timeoutMs                provider request timeout (default 10 000)
     * @param int|float                      $jwksMinRefreshIntervalMs minimum spacing of JWKS refreshes for unknown key IDs (default 30 000)
     * @param (\Closure(): (int|float))|null $now                      clock in milliseconds since the epoch (tests)
     * @param Store|null                     $cache                    shares the ID-token key set across requests
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        string $issuer,
        string $clientId,
        string $redirectUri,
        ?string $clientSecret = null,
        ?array $scopes = null,
        ?string $resource = null,
        ?array $algorithms = null,
        int|float $clockSkewMs = 30_000,
        int|float $timeoutMs = 10_000,
        int|float $jwksMinRefreshIntervalMs = 30_000,
        ?Transport $transport = null,
        ?\Closure $now = null,
        private readonly ?Store $cache = null,
    ) {
        $prefix = 'oidc-client';
        if ($issuer === '' || $clientId === '' || $redirectUri === '') {
            throw new \InvalidArgumentException('oidc-client: issuer, client ID and redirect URI are required');
        }
        $this->issuerOrigin = Url::requireHttp($issuer, 'issuer', $prefix)->origin();
        Url::requireHttp($redirectUri, 'redirectUri', $prefix);
        $this->issuer = $issuer;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret === null || $clientSecret === '' ? null : $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->scopes = $scopes === null || $scopes === [] ? ['openid'] : array_values($scopes);
        $this->resource = $resource === '' ? null : $resource;
        $this->algorithms = Signature::resolveAlgorithms($algorithms, $prefix);
        if (!is_finite((float) $clockSkewMs) || $clockSkewMs < 0 || $clockSkewMs > 60_000) {
            throw new \InvalidArgumentException('oidc-client: clock skew must be between 0 and 60s');
        }
        $this->skewMs = $clockSkewMs;
        if (!is_finite((float) $timeoutMs) || $timeoutMs <= 0) {
            throw new \InvalidArgumentException('oidc-client: timeoutMs must be positive');
        }
        $this->timeoutMs = (int) ceil($timeoutMs);
        if (!is_finite((float) $jwksMinRefreshIntervalMs) || $jwksMinRefreshIntervalMs < 1_000) {
            throw new \InvalidArgumentException('oidc-client: jwksMinRefreshIntervalMs must be at least 1000');
        }
        $this->minRefreshMs = $jwksMinRefreshIntervalMs;
        $this->http = new HttpClient($transport);
        $this->now = $now ?? Time::nowMs(...);
    }

    /** JWKS fetches made for ID-token validation (diagnostics and tests). */
    public function jwksFetchCount(): int
    {
        return $this->jwks?->fetchCount() ?? 0;
    }

    /**
     * Loads (once per instance) and returns the issuer's discovery document.
     *
     * @return array<string, mixed>
     *
     * @throws OidcException
     */
    public function discover(): array
    {
        return $this->metadata()->toArray();
    }

    private function metadata(): JsonObject
    {
        if ($this->meta === null) {
            $m = $this->getJson(rtrim($this->issuer, '/') . '/.well-known/openid-configuration');
            if ($m->get('issuer') !== $this->issuer) {
                throw new OidcException(OidcErrorCode::Provider, 'discovery issuer mismatch');
            }
            $this->meta = $m; // a failed load is retried on the next call
        }
        return $this->meta;
    }

    private function getJson(string $url): JsonObject
    {
        try {
            $res = $this->http->send('GET', $url, ['accept' => 'application/json'], null, $this->timeoutMs, 1 << 20);
        } catch (TransportException $e) {
            if ($e->kind === TransportException::TOO_LARGE && $e->status === 200) {
                throw new OidcException(OidcErrorCode::Provider, 'invalid metadata', previous: $e);
            }
            if ($e->kind === TransportException::TOO_LARGE && $e->status !== null) {
                throw new OidcException(OidcErrorCode::Provider, 'metadata request failed', status: $e->status);
            }
            throw new OidcException(OidcErrorCode::Provider, 'unreachable', previous: $e);
        }
        if ($res->status !== 200) {
            throw new OidcException(OidcErrorCode::Provider, 'metadata request failed', status: $res->status);
        }
        try {
            $v = StrictJson::decode($res->body);
        } catch (\Exception $e) {
            throw new OidcException(OidcErrorCode::Provider, 'invalid metadata', previous: $e);
        }
        if (!$v instanceof JsonObject) {
            throw new OidcException(OidcErrorCode::Provider, 'invalid metadata');
        }
        return $v;
    }

    private function endpoint(string $name): Url
    {
        $s = $this->metadata()->get($name);
        if (!is_string($s) || $s === '') {
            throw new OidcException(OidcErrorCode::Provider, "missing endpoint {$name}");
        }
        try {
            $u = Url::parse($s);
        } catch (\UnexpectedValueException $e) {
            if ($e->getMessage() === Url::NOT_ABSOLUTE) {
                throw new OidcException(OidcErrorCode::Provider, "invalid endpoint {$name}");
            }
            $u = null;
        }
        // Endpoints must live on the trusted issuer's origin.
        if ($u === null || $u->origin() !== $this->issuerOrigin) {
            throw new OidcException(OidcErrorCode::Provider, "endpoint {$name} is not on the issuer origin");
        }
        return $u;
    }

    /**
     * Builds an authorization request with state, nonce, PKCE S256 and the
     * resource indicator.
     *
     * @param array<string, string>|null $extraParams additional parameters (prompt, login_hint, ...); the
     *                                                security parameters cannot be set this way
     * @param list<string>|null          $scopes      default: the configured scopes
     *
     * @throws OidcException
     * @throws \InvalidArgumentException for a reserved extra parameter
     */
    public function authorizationUrl(?array $extraParams = null, ?array $scopes = null, ?string $resource = null): AuthRequest
    {
        $ep = $this->endpoint('authorization_endpoint');
        $scopes = $scopes !== null && $scopes !== [] ? array_values($scopes) : $this->scopes;
        $state = Pkce::randomValue();
        $nonce = Pkce::randomValue();
        $codeVerifier = Pkce::randomValue();
        $q = Query::parse($ep->query ?? '');
        $q->set('client_id', $this->clientId);
        $q->set('redirect_uri', $this->redirectUri);
        $q->set('response_type', 'code');
        $q->set('scope', implode(' ', $scopes));
        $q->set('state', $state);
        $q->set('nonce', $nonce);
        $q->set('code_challenge', Pkce::challenge($codeVerifier));
        $q->set('code_challenge_method', 'S256');
        $resource ??= $this->resource;
        if ($resource !== null && $resource !== '') {
            $q->set('resource', $resource);
        }
        foreach ($extraParams ?? [] as $k => $v) {
            $k = (string) $k;
            // Security parameters cannot be overridden through extra parameters.
            if (in_array($k, self::RESERVED_AUTH_PARAMS, true)) {
                throw new \InvalidArgumentException("oidc-client: {$k} cannot be set through extraParams");
            }
            $q->set($k, (string) $v);
        }
        return new AuthRequest(
            $state,
            $nonce,
            $codeVerifier,
            $ep->withQuery($q->toString())->toString(),
            $this->redirectUri,
            $scopes,
            ($this->now)(),
        );
    }

    /**
     * Validates the callback (state, RFC 9207 issuer), redeems the code with
     * the PKCE verifier and validates the ID token (nonce, at_hash) before
     * returning tokens.
     *
     * @param string|array<string, mixed> $callback the callback URL, its request target or query string
     *                                              (e.g. $_SERVER['REQUEST_URI'], which keeps duplicate
     *                                              parameters detectable), or its parameters ($_GET)
     *
     * @throws OidcException
     */
    public function exchangeCode(AuthRequest $authRequest, string|array $callback): CodeExchangeResult
    {
        $params = self::toParams($callback);
        $one = static function (string $k) use ($params): ?string {
            $all = $params->getAll($k);
            if (count($all) > 1) {
                throw new OidcException(OidcErrorCode::Provider, "duplicate {$k} parameter");
            }
            return $all[0] ?? null;
        };
        $error = $one('error');
        $state = $one('state');
        if ($state === null || $state === '' || !hash_equals($authRequest->state, $state)) {
            throw new OidcException(OidcErrorCode::State);
        }
        $meta = $this->metadata();
        $iss = $one('iss');
        if ($iss !== null && $iss !== $this->issuer) {
            throw new OidcException(OidcErrorCode::Provider, 'authorization response issuer mismatch (mix-up)');
        }
        if ($iss === null && $meta->get('authorization_response_iss_parameter_supported') === true) {
            throw new OidcException(OidcErrorCode::Provider, 'authorization response is missing iss');
        }
        if ($error !== null) {
            throw new OidcException(OidcErrorCode::Provider, providerError: self::safeCode($error));
        }
        $code = $one('code');
        if ($code === null || $code === '') {
            throw new OidcException(OidcErrorCode::Provider, 'missing authorization code');
        }

        $tokens = $this->tokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'code_verifier' => $authRequest->codeVerifier,
            'redirect_uri' => $authRequest->redirectUri,
        ]);
        $idClaims = null;
        if ($tokens->idToken !== null) {
            $idClaims = $this->validateIdToken($tokens->idToken, nonce: $authRequest->nonce, accessToken: $tokens->accessToken);
        } elseif (in_array('openid', $authRequest->scopes, true)) {
            throw new OidcException(OidcErrorCode::IdToken, 'missing ID token');
        }
        return new CodeExchangeResult($tokens, $idClaims);
    }

    /**
     * Token endpoint call (code exchange and refresh).
     *
     * @param array<string, string> $fields
     */
    private function tokenRequest(array $fields): TokenSet
    {
        $ep = $this->endpoint('token_endpoint');
        $headers = ['content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json'];
        $form = $fields;
        if ($this->clientSecret !== null) {
            $headers['authorization'] = HttpClient::basicAuthorization($this->clientId, $this->clientSecret);
        } else {
            $form['client_id'] = $this->clientId;
        }
        $res = null;
        $status = null;
        try {
            $res = $this->http->send('POST', $ep->toString(), $headers, HttpClient::formBody($form), $this->timeoutMs, 1 << 20);
            $status = $res->status;
        } catch (TransportException $e) {
            if ($e->kind !== TransportException::TOO_LARGE || $e->status === null) {
                throw new OidcException(OidcErrorCode::Provider, 'token endpoint unreachable', previous: $e);
            }
            $status = $e->status; // the body could not be read
        }
        $body = null;
        $parseError = null;
        try {
            if (!$res instanceof Response) {
                throw new \RuntimeException('response body exceeds the configured limit');
            }
            $body = StrictJson::decode($res->body);
        } catch (\Exception $e) {
            $parseError = $e;
            if ($status === 200) {
                throw new OidcException(OidcErrorCode::Provider, 'invalid token response', status: 200, previous: $e);
            }
        }
        if ($status !== 200) {
            $err = $body instanceof JsonObject && is_string($body->get('error')) ? $body->get('error') : null;
            if ($err === 'invalid_grant') {
                throw new OidcException(OidcErrorCode::Reauthenticate, providerError: $err, status: $status);
            }
            throw new OidcException(OidcErrorCode::Provider, 'token endpoint error', $err !== null ? self::safeCode($err) : null, $status, $parseError);
        }
        if (!$body instanceof JsonObject) {
            throw new OidcException(OidcErrorCode::Provider, 'invalid token response');
        }
        $at = $body->get('access_token');
        $tt = $body->get('token_type');
        $ei = $body->get('expires_in');
        $rt = $body->get('refresh_token');
        $it = $body->get('id_token');
        $scope = $body->get('scope');
        if (!is_string($at) || $at === '') {
            throw new OidcException(OidcErrorCode::Provider, 'missing access_token');
        }
        if (!is_string($tt) || strtolower($tt) !== 'bearer') {
            throw new OidcException(OidcErrorCode::Provider, 'unsupported token_type');
        }
        if ($body->has('expires_in') && (!(is_int($ei) || (is_float($ei) && is_finite($ei))) || $ei < 0)) {
            throw new OidcException(OidcErrorCode::Provider, 'invalid expires_in');
        }
        $expiresIn = is_int($ei) || is_float($ei) ? $ei : 0;
        return new TokenSet(
            $at,
            $tt,
            $expiresIn,
            is_string($rt) && $rt !== '' ? $rt : null,
            is_string($it) && $it !== '' ? $it : null,
            is_string($scope) ? $scope : null,
            ($this->now)() + $expiresIn * 1000,
        );
    }

    /**
     * Verifies the ID-token signature and then its claims: exact issuer,
     * audience containing this client, azp for multi-audience tokens, expiry,
     * issued-at, nonce, at_hash and max_age (OIDC-016). The payload is never
     * trusted before the signature.
     *
     * @param string|null    $nonce       the nonce sent in the authorization request; required to match when given
     * @param string|null    $accessToken the access token issued with the ID token; checked against at_hash when present
     * @param int|float|null $maxAgeSec   maximum authentication age in seconds (requires auth_time)
     *
     * @throws OidcException
     */
    public function validateIdToken(string $raw, ?string $nonce = null, ?string $accessToken = null, int|float|null $maxAgeSec = null): IdTokenClaims
    {
        $bad = static fn (string $reason): OidcException => new OidcException(OidcErrorCode::IdToken, $reason);
        if ($raw === '' || strlen($raw) > 16384) {
            throw $bad('size');
        }
        try {
            $jws = Jws::parse($raw);
        } catch (JwsException $e) {
            throw $bad($e->reason === JwsException::DUPLICATE ? 'duplicate member' : 'malformed');
        }
        $header = $jws->header;
        if ($header->has('crit')) {
            throw $bad('critical header');
        }
        $alg = $header->get('alg');
        if (!is_string($alg) || !isset($this->algorithms[$alg])) {
            throw $bad('algorithm');
        }
        if ($header->has('typ') && (!is_string($header->get('typ')) || strtolower($header->get('typ')) !== 'jwt')) {
            throw $bad('type'); // an access token (at+jwt) is not an ID token
        }
        $kid = $header->get('kid');
        if (!is_string($kid) || $kid === '') {
            throw $bad('missing kid');
        }
        $jwks = $this->keySet();
        try {
            $key = $jwks->getKey($kid);
        } catch (JwksException $e) {
            if ($e->reason === JwksException::UNKNOWN_KEY) {
                throw $bad('unknown key');
            }
            throw new OidcException(OidcErrorCode::Provider, 'key set unavailable', previous: $e);
        }
        if ($key->alg !== null && $key->alg !== $alg) {
            throw $bad('algorithm');
        }
        if (!Signature::verify($alg, $key, $jws->signingInput, $jws->signature)) {
            throw $bad('signature');
        }

        $p = $jws->payload;
        $optStr = static function (string $k) use ($p, $bad): ?string {
            $v = $p->get($k);
            if ($v === null) {
                return null;
            }
            if (!is_string($v)) {
                throw $bad("claim {$k}");
            }
            return $v;
        };
        $optNum = static function (string $k) use ($p, $bad): int|float|null {
            $v = $p->get($k);
            if ($v === null) {
                return null;
            }
            if (!(is_int($v) || (is_float($v) && is_finite($v)))) {
                throw $bad("claim {$k}");
            }
            return $v;
        };
        $aud = $p->get('aud');
        if (is_string($aud)) {
            $audience = [$aud];
        } elseif (is_array($aud) && count(array_filter($aud, 'is_string')) === count($aud)) {
            $audience = $aud;
        } else {
            throw $bad('audience');
        }
        $iss = $optStr('iss');
        $sub = $optStr('sub');
        $azp = $optStr('azp');
        $exp = $optNum('exp');
        $iat = $optNum('iat');
        $authTime = $optNum('auth_time');
        $tokenNonce = $optStr('nonce');
        $atHash = $optStr('at_hash');
        $nowSec = (float) ($this->now)() / 1000;
        $skewSec = $this->skewMs / 1000;
        if ($iss !== $this->issuer) {
            throw $bad('issuer');
        }
        if ($sub === null || $sub === '') {
            throw $bad('subject');
        }
        if (!in_array($this->clientId, $audience, true)) {
            throw $bad('audience');
        }
        if (count($audience) > 1 && $azp !== $this->clientId) {
            throw $bad('authorized party');
        }
        if ($azp !== null && $azp !== $this->clientId) {
            throw $bad('authorized party');
        }
        if ($exp === null || $nowSec > $exp + $skewSec) {
            throw $bad('expired');
        }
        if ($iat !== null && $iat > $nowSec + $skewSec) {
            throw $bad('issued in the future');
        }
        if ($nonce !== null && $nonce !== '' && ($tokenNonce === null || !hash_equals($nonce, $tokenNonce))) {
            throw new OidcException(OidcErrorCode::Nonce);
        }
        if ($accessToken !== null && $accessToken !== '' && $atHash !== null && !hash_equals(Pkce::halfHash($alg, $accessToken), $atHash)) {
            throw $bad('at_hash');
        }
        if ($maxAgeSec !== null && ($authTime === null || $nowSec - $authTime > $maxAgeSec + $skewSec)) {
            throw $bad('max_age');
        }
        $amr = $p->get('amr');
        $amr = is_array($amr) ? array_values(array_filter($amr, 'is_string')) : [];
        $acr = $optStr('acr');
        $sid = $optStr('sid');
        $email = $p->get('email');
        $name = $p->get('name');
        return new IdTokenClaims(
            issuer: $iss,
            subject: $sub,
            audience: array_values($audience),
            expiry: Time::fromUnixSeconds($exp),
            issuedAt: $iat !== null ? Time::fromUnixSeconds($iat) : null,
            authTime: $authTime !== null && $authTime > 0 ? Time::fromUnixSeconds($authTime) : null,
            nonce: $tokenNonce,
            acr: $acr,
            amr: $amr,
            azp: $azp,
            sid: $sid,
            atHash: $atHash,
            email: is_string($email) ? $email : null,
            name: is_string($name) ? $name : null,
            claims: $p->toArray(),
        );
    }

    private function keySet(): JwksCache
    {
        if ($this->jwks === null) {
            $url = $this->endpoint('jwks_uri');
            $this->jwks = new JwksCache($url->toString(), $this->http, $this->timeoutMs, $this->minRefreshMs, $this->now, $this->cache);
        }
        return $this->jwks;
    }

    /**
     * Wraps tokens in a Session that refreshes them. Keep one Session per
     * browser session; restore it on every request from your server-side
     * session storage.
     *
     * @param (\Closure(TokenSet): void)|null      $onRefresh       called after every successful refresh so the new (rotated)
     *                                                              tokens can be persisted server-side
     * @param int|float                            $refreshWindowMs refresh when the access token expires within this window
     *                                                              (default 15 000)
     * @param (\Closure(\Closure): mixed)|null     $lock            runs the given closure while holding an exclusive lock for this
     *                                                              browser session, so concurrent PHP requests never present the
     *                                                              same refresh token twice (see FileRefreshLock::for())
     * @param (\Closure(): ?TokenSet)|null         $reload          reads the currently stored tokens inside the lock (another
     *                                                              request may have rotated them already); null means logged out
     */
    public function session(
        TokenSet $tokens,
        ?IdTokenClaims $idClaims = null,
        ?\Closure $onRefresh = null,
        int|float $refreshWindowMs = 15_000,
        ?\Closure $lock = null,
        ?\Closure $reload = null,
    ): Session {
        return new Session(
            fn (array $fields): TokenSet => $this->tokenRequest($fields),
            fn (string $idToken, string $accessToken): IdTokenClaims => $this->validateIdToken($idToken, accessToken: $accessToken),
            $this->now,
            $tokens,
            $idClaims,
            $onRefresh,
            $refreshWindowMs,
            $lock,
            $reload,
        );
    }

    /**
     * Revokes a token at the provider (RFC 7009); used at logout.
     *
     * @param string $tokenTypeHint "refresh_token" (default) or "access_token"
     *
     * @throws OidcException
     */
    public function revoke(string $token, string $tokenTypeHint = 'refresh_token'): void
    {
        if ($token === '') {
            return;
        }
        $ep = $this->endpoint('revocation_endpoint');
        $headers = ['content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json'];
        $form = ['token' => $token, 'token_type_hint' => $tokenTypeHint];
        if ($this->clientSecret !== null) {
            $headers['authorization'] = HttpClient::basicAuthorization($this->clientId, $this->clientSecret);
        } else {
            $form['client_id'] = $this->clientId;
        }
        try {
            $status = $this->http->send('POST', $ep->toString(), $headers, HttpClient::formBody($form), $this->timeoutMs, 64 << 10)->status;
        } catch (TransportException $e) {
            if ($e->kind !== TransportException::TOO_LARGE || $e->status === null) {
                throw new OidcException(OidcErrorCode::Provider, 'revocation endpoint unreachable', previous: $e);
            }
            $status = $e->status; // the body is irrelevant
        }
        if ($status !== 200) {
            throw new OidcException(OidcErrorCode::Provider, 'revocation failed', status: $status);
        }
    }

    /**
     * Builds an RP-initiated logout URL.
     *
     * @throws OidcException
     */
    public function logoutUrl(?string $idTokenHint = null, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        $ep = $this->endpoint('end_session_endpoint');
        $q = Query::parse($ep->query ?? '');
        if ($idTokenHint !== null && $idTokenHint !== '') {
            $q->set('id_token_hint', $idTokenHint);
        }
        $q->set('client_id', $this->clientId);
        if ($postLogoutRedirectUri !== null && $postLogoutRedirectUri !== '') {
            $q->set('post_logout_redirect_uri', $postLogoutRedirectUri);
        }
        if ($state !== null && $state !== '') {
            $q->set('state', $state);
        }
        return $ep->withQuery($q->toString())->toString();
    }

    /**
     * Ends a session: clears it locally, revokes its refresh token and returns
     * the RP-initiated logout URL. The local session is cleared even when
     * revocation fails (the error is then thrown after clearing).
     *
     * @throws OidcException
     */
    public function logout(Session $session, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        $tokens = $session->tokens();
        $session->clear();
        $url = $this->logoutUrl($tokens?->idToken, $postLogoutRedirectUri, $state);
        if ($tokens !== null && $tokens->refreshToken !== null) {
            $this->revoke($tokens->refreshToken, 'refresh_token');
        }
        return $url;
    }

    /** Hides the client secret from var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return ['issuer' => $this->issuer, 'clientId' => $this->clientId, 'redirectUri' => $this->redirectUri, 'scopes' => $this->scopes];
    }

    /** @param string|array<string, mixed> $callback */
    private static function toParams(string|array $callback): Query
    {
        if (is_array($callback)) {
            return Query::fromArray($callback);
        }
        if (preg_match('#^https?://#i', $callback) === 1) {
            $q = strpos($callback, '?');
            if ($q === false) {
                return Query::parse('');
            }
            return Query::parse(explode('#', substr($callback, $q + 1), 2)[0]);
        }
        $q = strpos($callback, '?');
        return Query::parse($q !== false ? substr($callback, $q + 1) : $callback);
    }

    /** Provider error codes are echoed only when they look like OAuth error codes. */
    private static function safeCode(string $s): string
    {
        return preg_match('/^[a-z0-9_.\-]{1,64}$/Di', $s) === 1 ? $s : 'unrecognized_error';
    }
}

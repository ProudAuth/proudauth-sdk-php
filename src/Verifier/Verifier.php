<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Verifier;

use ProudAuth\Sdk\Cache\Store;
use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Internal\Jose\Jws;
use ProudAuth\Sdk\Internal\Jose\JwsException;
use ProudAuth\Sdk\Internal\Jose\Signature;
use ProudAuth\Sdk\Internal\Json\JsonObject;
use ProudAuth\Sdk\Internal\JwksCache;
use ProudAuth\Sdk\Internal\JwksException;
use ProudAuth\Sdk\Internal\Text;
use ProudAuth\Sdk\Internal\Time;
use ProudAuth\Sdk\Internal\Url;

/**
 * Offline JWT access-token verification for resource servers (SDK-001), a
 * port of the Node and Go SDKs' verifiers.
 *
 * Offline mode verifies JWT access tokens with the §14.4 algorithm: a
 * preconfigured trusted issuer (checked before any key fetch), strict parsing
 * with duplicate-member rejection, explicit "at+jwt" typing, an asymmetric
 * algorithm allowlist, key IDs resolved only from that issuer's configured key
 * set with bounded refreshes, exact issuer and audience checks, and
 * fail-closed errors.
 *
 * Offline verification cannot observe revocation before expiry (SES-023): a
 * revoked session's access token keeps working until `exp` plus the clock
 * skew. Use the strict-online Introspector where that exposure is
 * unacceptable, and always for support (impersonation) tokens.
 */
final class Verifier implements Authenticator
{
    /** Asymmetric algorithms the SDK verifies. */
    public const SUPPORTED_ALGORITHMS = Signature::SUPPORTED_ALGORITHMS;

    /** Token kinds accepted offline by default. */
    public const DEFAULT_ACCEPTED_KINDS = ['user_access', 'service_access', 'exchange_access'];

    /** Support tokens are opaque and strict-online only (IMP-010). */
    public const SUPPORT_TOKEN_KIND = 'impersonation_access';

    public const MAX_CLOCK_SKEW_MS = 60_000;

    public readonly string $issuer;
    public readonly string $audience;

    /** @var array<string, true> */
    private readonly array $algorithms;
    private readonly int|float $skewMs;
    /** @var list<string> */
    private readonly array $acceptedKinds;
    private readonly int $maxTokenBytes;
    /** @var \Closure(): (int|float) */
    private readonly \Closure $now;
    private readonly JwksCache $jwks;

    /**
     * @param string                       $issuer               the exact trusted issuer; tokens from any other issuer are
     *                                                           rejected without fetching anything (TEST-003)
     * @param string                       $audience             this API's registered audience
     * @param string|null                  $jwksUrl              default "{issuer}/jwks"; never taken from a token (no jku/x5u)
     * @param list<string>|null            $algorithms           allowlist; default RS256, PS256, ES256, EdDSA; "none" and HS* are refused
     * @param int|float                    $clockSkewMs          permitted clock tolerance (default 30 000, at most 60 000)
     * @param list<string>|null            $acceptedKinds        accepted token_kind values; default user_access, service_access,
     *                                                           exchange_access; impersonation_access is refused (use SupportGuard)
     * @param int|float                    $minRefreshIntervalMs minimum spacing of key-set refreshes triggered by unknown key IDs
     *                                                           (default 30 000, minimum 1 000)
     * @param int                          $maxTokenBytes        maximum token size (default 8192)
     * @param int|float                    $timeoutMs            key-set request timeout (default 5 000)
     * @param Transport|null               $transport            default CurlTransport
     * @param (\Closure(): (int|float))|null $now                clock in milliseconds since the epoch (tests)
     * @param Store|null                   $cache                shares the key set and refresh bookkeeping across requests and
     *                                                           workers (default: this object only)
     *
     * @throws \InvalidArgumentException on invalid configuration
     */
    public function __construct(
        string $issuer,
        string $audience,
        ?string $jwksUrl = null,
        ?array $algorithms = null,
        int|float $clockSkewMs = 30_000,
        ?array $acceptedKinds = null,
        int|float $minRefreshIntervalMs = 30_000,
        int $maxTokenBytes = 8192,
        int|float $timeoutMs = 5_000,
        ?Transport $transport = null,
        ?\Closure $now = null,
        ?Store $cache = null,
    ) {
        $prefix = 'verifier';
        if ($issuer === '' || $audience === '') {
            throw new \InvalidArgumentException('verifier: issuer and audience are required');
        }
        $this->issuer = $issuer;
        $this->audience = $audience;
        $jwksUrl ??= rtrim($issuer, '/') . '/jwks';
        $jwks = Url::requireHttp($jwksUrl, 'jwksUrl', $prefix);
        $this->algorithms = Signature::resolveAlgorithms($algorithms, $prefix);
        if (!is_finite((float) $clockSkewMs) || $clockSkewMs < 0) {
            throw new \InvalidArgumentException('verifier: clock skew must be a non-negative number of milliseconds');
        }
        if ($clockSkewMs > self::MAX_CLOCK_SKEW_MS) {
            throw new \InvalidArgumentException('verifier: clock skew must be at most 60s');
        }
        $this->skewMs = $clockSkewMs;
        $kinds = $acceptedKinds === null || $acceptedKinds === [] ? self::DEFAULT_ACCEPTED_KINDS : array_values($acceptedKinds);
        if (in_array(self::SUPPORT_TOKEN_KIND, $kinds, true)) {
            throw new \InvalidArgumentException('verifier: impersonation_access cannot be verified offline; use the SupportGuard (strict-online)');
        }
        $this->acceptedKinds = $kinds;
        if (!is_finite((float) $minRefreshIntervalMs) || $minRefreshIntervalMs < 1_000) {
            throw new \InvalidArgumentException('verifier: minRefreshIntervalMs must be at least 1000');
        }
        if ($maxTokenBytes <= 0) {
            throw new \InvalidArgumentException('verifier: maxTokenBytes must be a positive integer');
        }
        $this->maxTokenBytes = $maxTokenBytes;
        if (!is_finite((float) $timeoutMs) || $timeoutMs <= 0) {
            throw new \InvalidArgumentException('verifier: timeoutMs must be positive');
        }
        $this->now = $now ?? Time::nowMs(...);
        $this->jwks = new JwksCache(
            $jwks->toString(),
            new HttpClient($transport),
            (int) ceil($timeoutMs),
            $minRefreshIntervalMs,
            $this->now,
            $cache,
        );
    }

    /** How many key-set fetches this instance made (diagnostics and tests). */
    public function fetchCount(): int
    {
        return $this->jwks->fetchCount();
    }

    /**
     * Verifies a JWT access token offline.
     *
     * @throws VerifierException
     */
    public function verify(string $raw): Claims
    {
        if ($raw === '') {
            throw new VerifierException(VerifierErrorCode::MissingToken);
        }
        if (strlen($raw) > $this->maxTokenBytes) {
            throw new VerifierException(VerifierErrorCode::TooLarge);
        }
        try {
            $jws = Jws::parse($raw);
        } catch (JwsException $e) {
            throw new VerifierException($e->reason === JwsException::DUPLICATE ? VerifierErrorCode::DuplicateClaim : VerifierErrorCode::Malformed);
        }
        $header = $jws->header;
        $payload = $jws->payload;

        // Check the issuer before any key lookup so unrelated issuers never trigger fetches.
        if ($payload->get('iss') !== $this->issuer) {
            throw new VerifierException(VerifierErrorCode::Issuer);
        }

        // No JOSE extensions are understood, so a critical one cannot be honoured.
        if ($header->has('crit')) {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        $alg = $header->get('alg');
        if (!is_string($alg) || !isset($this->algorithms[$alg])) {
            throw new VerifierException(VerifierErrorCode::Algorithm);
        }
        $typ = $header->get('typ');
        $typ = is_string($typ) ? strtolower($typ) : '';
        if ($typ !== 'at+jwt' && $typ !== 'application/at+jwt') {
            throw new VerifierException(VerifierErrorCode::TokenType); // e.g. an ID token sent to an API (TEST-002)
        }
        $kid = $header->get('kid');
        if (!is_string($kid) || $kid === '') {
            throw new VerifierException(VerifierErrorCode::UnknownKey);
        }

        try {
            $key = $this->jwks->getKey($kid);
        } catch (JwksException $e) {
            if ($e->reason === JwksException::UNKNOWN_KEY) {
                throw new VerifierException(VerifierErrorCode::UnknownKey);
            }
            throw new VerifierException(VerifierErrorCode::Unavailable, $e);
        }
        if ($key->alg !== null && $key->alg !== $alg) {
            throw new VerifierException(VerifierErrorCode::Algorithm);
        }
        if (!Signature::verify($alg, $key, $jws->signingInput, $jws->signature)) {
            throw new VerifierException(VerifierErrorCode::Signature);
        }

        return $this->claims($payload);
    }

    /** Implements Authenticator for offline verification. */
    public function authenticate(string $raw): Claims
    {
        return $this->verify($raw);
    }

    private function claims(JsonObject $p): Claims
    {
        $str = static function (string $k) use ($p): string {
            $v = $p->get($k);
            if ($v === null) {
                return '';
            }
            if (!is_string($v)) {
                throw new VerifierException(VerifierErrorCode::Malformed);
            }
            return $v;
        };
        $num = static function (string $k) use ($p): int|float|null {
            $v = $p->get($k);
            if ($v === null) {
                return null;
            }
            if (!(is_int($v) || (is_float($v) && is_finite($v)))) {
                throw new VerifierException(VerifierErrorCode::Malformed);
            }
            return $v;
        };

        if ($str('iss') !== $this->issuer) {
            throw new VerifierException(VerifierErrorCode::Issuer);
        }

        $aud = $p->get('aud');
        if (is_string($aud)) {
            $audiences = [$aud];
        } elseif ($aud === null) {
            $audiences = [];
        } elseif (is_array($aud) && count(array_filter($aud, 'is_string')) === count($aud)) {
            $audiences = $aud;
        } else {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        // Exactly one audience, equal to this API's (narrow audiences, TOK-007, TEST-001).
        if (count($audiences) !== 1 || $audiences[0] !== $this->audience) {
            throw new VerifierException(VerifierErrorCode::Audience);
        }

        $nowSec = (float) ($this->now)() / 1000;
        $skewSec = $this->skewMs / 1000;
        $exp = $num('exp');
        $nbf = $num('nbf');
        $iat = $num('iat');
        if ($exp === null || $nowSec > $exp + $skewSec) {
            throw new VerifierException(VerifierErrorCode::Expired);
        }
        if ($nbf !== null && $nowSec + $skewSec < $nbf) {
            throw new VerifierException(VerifierErrorCode::NotYetValid);
        }
        if ($iat !== null && $iat > $nowSec + $skewSec) {
            throw new VerifierException(VerifierErrorCode::FutureIssued);
        }

        $subject = $str('sub');
        $clientId = $str('client_id');
        $jti = $str('jti');
        $tokenKind = $str('token_kind');
        if ($subject === '' || $clientId === '' || $jti === '' || !in_array($tokenKind, $this->acceptedKinds, true)) {
            throw new VerifierException(VerifierErrorCode::TokenKind);
        }
        $scope = $str('scope');
        $authTime = $num('auth_time');
        $act = $p->get('act');
        $actor = $act === null ? null : self::actorStrict($act, 0);
        $orgId = $str('org_id');
        $sessionId = $str('sid');
        $acr = $str('acr');
        $authzVersion = $num('authz_version') ?? 0;
        if ($p->has('cnf')) {
            throw new VerifierException(VerifierErrorCode::SenderConstraint);
        }
        return new Claims(
            issuer: $this->issuer,
            subject: $subject,
            audience: $this->audience,
            clientId: $clientId,
            scopes: Text::splitWhitespace($scope),
            orgId: $orgId,
            sessionId: $sessionId,
            tokenKind: $tokenKind,
            jti: $jti,
            acr: $acr,
            authzVersion: $authzVersion,
            online: false,
            issuedAt: $iat !== null ? Time::fromUnixSeconds($iat) : null,
            expiry: Time::fromUnixSeconds($exp),
            authTime: $authTime !== null && $authTime > 0 ? Time::fromUnixSeconds($authTime) : null,
            actor: $actor,
        );
    }

    private static function actorStrict(mixed $v, int $depth): Actor
    {
        if ($depth > 16 || !$v instanceof JsonObject) {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        $sub = $v->get('sub');
        $iss = $v->get('iss');
        if (!is_string($sub) || ($v->has('iss') && !is_string($iss))) {
            throw new VerifierException(VerifierErrorCode::Malformed);
        }
        $act = $v->get('act');
        return new Actor($sub, is_string($iss) ? $iss : null, $act === null ? null : self::actorStrict($act, $depth + 1));
    }
}

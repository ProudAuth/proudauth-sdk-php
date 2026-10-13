<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Introspection;

use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Internal\Json\JsonObject;
use ProudAuth\Sdk\Internal\Json\StrictJson;
use ProudAuth\Sdk\Internal\Text;
use ProudAuth\Sdk\Internal\Time;
use ProudAuth\Sdk\Internal\Url;
use ProudAuth\Sdk\Verifier\Actor;
use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Strict-online token validation (§13.2, SDK-002), a port of the Node and Go
 * SDKs' Introspector.
 *
 * Every call consults the identity provider's authoritative state through
 * RFC 7662 introspection. There is no positive cache, and any failure
 * (network error, timeout, non-200, unparsable response) denies with an
 * `unavailable` error rather than downgrading to offline checks (TEST-035).
 */
final class Introspector implements Authenticator
{
    /** Token kinds accepted by default (support tokens only via SupportGuard). */
    public const DEFAULT_ONLINE_KINDS = ['user_access', 'service_access', 'exchange_access', 'api_key', 'personal_access'];

    public const SUPPORT_TOKEN_KIND = 'impersonation_access';

    private const MAX_RESPONSE_BYTES = 64 << 10;

    public readonly string $issuer;
    public readonly string $audience;

    private readonly string $endpoint;
    private readonly string $authorization;
    private readonly int $timeoutMs;
    /** @var list<string> */
    private readonly array $kinds;
    private readonly int $maxTokenBytes;
    private readonly HttpClient $http;

    /**
     * @param string            $endpoint      the issuer's introspection endpoint, e.g. "{issuer}/oauth/introspect"
     * @param string            $clientId      this resource server's confidential client (client_secret_basic)
     * @param string            $clientSecret  sent in the Authorization header, never logged
     * @param string            $issuer        exact expected issuer of introspected tokens
     * @param string            $audience      this API's audience; tokens for any other audience are rejected
     * @param int|float         $timeoutMs     per-request deadline (default 3 000); timeouts deny
     * @param list<string>|null $acceptedKinds accepted token_kind values for authenticate() (default DEFAULT_ONLINE_KINDS);
     *                                         impersonation_access is refused: support tokens go through SupportGuard
     * @param int               $maxTokenBytes tokens longer than this are rejected without a network call (default 8192)
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        string $endpoint,
        string $clientId,
        string $clientSecret,
        string $issuer,
        string $audience,
        int|float $timeoutMs = 3_000,
        ?array $acceptedKinds = null,
        int $maxTokenBytes = 8192,
        ?Transport $transport = null,
    ) {
        $this->endpoint = Url::requireHttp($endpoint, 'endpoint', 'introspection')->toString();
        foreach (['clientId' => $clientId, 'clientSecret' => $clientSecret, 'issuer' => $issuer, 'audience' => $audience] as $k => $v) {
            if ($v === '') {
                throw new \InvalidArgumentException("introspection: {$k} is required");
            }
        }
        $this->authorization = HttpClient::basicAuthorization($clientId, $clientSecret);
        $this->issuer = $issuer;
        $this->audience = $audience;
        if (!is_finite((float) $timeoutMs) || $timeoutMs <= 0) {
            throw new \InvalidArgumentException('introspection: timeoutMs must be positive');
        }
        $this->timeoutMs = (int) ceil($timeoutMs);
        $kinds = $acceptedKinds === null || $acceptedKinds === [] ? self::DEFAULT_ONLINE_KINDS : array_values($acceptedKinds);
        if (in_array(self::SUPPORT_TOKEN_KIND, $kinds, true)) {
            throw new \InvalidArgumentException('introspection: impersonation_access must be handled by a SupportGuard, not accepted as an ordinary kind');
        }
        $this->kinds = $kinds;
        $this->maxTokenBytes = $maxTokenBytes;
        $this->http = new HttpClient($transport);
    }

    /**
     * Verifies a non-support token online.
     *
     * @throws VerifierException
     */
    public function authenticate(string $raw): Claims
    {
        $c = $this->introspect($raw);
        if (!$this->acceptsKind($c->tokenKind)) {
            // A support token presented to an API path that has not implemented the
            // support contract is rejected (IMP-001, TEST-045).
            throw new VerifierException(VerifierErrorCode::TokenKind);
        }
        return $c;
    }

    /** Hides the client credentials from var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return ['endpoint' => $this->endpoint, 'issuer' => $this->issuer, 'audience' => $this->audience];
    }

    /**
     * Introspects and checks issuer and audience; no token-kind policy.
     * Reachable only from this class and SupportGuard (which binds to it).
     */
    private function introspect(string $raw): Claims
    {
        if ($raw === '') {
            throw new VerifierException(VerifierErrorCode::MissingToken);
        }
        if (strlen($raw) > $this->maxTokenBytes) {
            throw new VerifierException(VerifierErrorCode::TooLarge);
        }
        try {
            $res = $this->http->send(
                'POST',
                $this->endpoint,
                [
                    'authorization' => $this->authorization,
                    'content-type' => 'application/x-www-form-urlencoded',
                    'accept' => 'application/json',
                ],
                HttpClient::formBody(['token' => $raw]),
                $this->timeoutMs,
                self::MAX_RESPONSE_BYTES,
            );
            if ($res->status !== 200) {
                throw new \RuntimeException('introspection endpoint returned HTTP ' . $res->status);
            }
            $m = StrictJson::decode($res->body);
        } catch (\Exception $cause) {
            throw new VerifierException(VerifierErrorCode::Unavailable, $cause);
        }
        if (!$m instanceof JsonObject) {
            throw new VerifierException(VerifierErrorCode::Unavailable);
        }
        if ($m->get('active') !== true) {
            throw new VerifierException(VerifierErrorCode::Inactive);
        }
        $c = self::toClaims($m);
        if ($c->issuer !== $this->issuer) {
            throw new VerifierException(VerifierErrorCode::Issuer);
        }
        if ($c->audience !== $this->audience) {
            throw new VerifierException(VerifierErrorCode::Audience);
        }
        return $c;
    }

    private function acceptsKind(string $kind): bool
    {
        return in_array($kind, $this->kinds, true);
    }

    private static function toClaims(JsonObject $m): Claims
    {
        if ($m->has('cnf')) {
            throw new VerifierException(VerifierErrorCode::SenderConstraint);
        }
        $str = static fn (string $k): string => is_string($v = $m->get($k)) ? $v : '';
        $num = static function (string $k) use ($m): int|float {
            $v = $m->get($k);
            if (is_int($v)) {
                return $v;
            }
            if (!is_float($v) || !is_finite($v)) {
                return 0;
            }
            $t = $v < 0 ? ceil($v) : floor($v);
            return abs($t) < 9.0e18 ? (int) $t : $t;
        };
        $date = static function (string $k) use ($num): ?\DateTimeImmutable {
            $v = $num($k);
            return $v > 0 ? Time::fromUnixSeconds($v) : null;
        };
        $aud = $m->get('aud');
        $audience = '';
        if (is_string($aud)) {
            $audience = $aud;
        } elseif (is_array($aud) && count($aud) === 1 && is_string($aud[0])) {
            $audience = $aud[0];
        }
        return new Claims(
            issuer: $str('iss'),
            subject: $str('sub'),
            audience: $audience,
            clientId: $str('client_id'),
            scopes: Text::splitWhitespace($str('scope')),
            orgId: $str('org_id'),
            sessionId: $str('sid'),
            tokenKind: $str('token_kind'),
            jti: $str('jti'),
            acr: $str('acr'),
            authzVersion: $num('authz_version'),
            online: true,
            issuedAt: $date('iat'),
            expiry: $date('exp'),
            authTime: $date('auth_time'),
            actor: self::actorLenient($m->get('act'), 0),
            supportMode: $str('support_mode'),
            impersonationGrantId: $str('impersonation_grant_id'),
        );
    }

    private static function actorLenient(mixed $v, int $depth): ?Actor
    {
        if ($depth > 16 || !$v instanceof JsonObject) {
            return null;
        }
        $sub = $v->get('sub');
        $iss = $v->get('iss');
        return new Actor(is_string($sub) ? $sub : '', is_string($iss) ? $iss : null, self::actorLenient($v->get('act'), $depth + 1));
    }
}

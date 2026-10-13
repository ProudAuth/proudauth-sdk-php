<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Cache\MemoryStore;
use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Oidc\AuthRequest;
use ProudAuth\Sdk\Oidc\FileRefreshLock;
use ProudAuth\Sdk\Oidc\OidcClient;
use ProudAuth\Sdk\Oidc\OidcErrorCode as O;
use ProudAuth\Sdk\Oidc\OidcException;
use ProudAuth\Sdk\Oidc\Pkce;
use ProudAuth\Sdk\Oidc\Session;
use ProudAuth\Sdk\Oidc\TokenSet;
use ProudAuth\Sdk\Tests\Support\Clock;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Tests\Support\Jwt;
use ProudAuth\Sdk\Tests\Support\TestKey;

/**
 * Port of sdk/node/test/oidc-client.test.ts against an in-process IdP that
 * rotates refresh tokens and revokes the whole family on reuse, like the
 * server (SES-007/008).
 */
final class OidcClientTest extends TestCase
{
    private const ISSUER = 'https://idp.test/realms/main';
    private const CLIENT_ID = 'customer-web-bff';
    private const CLIENT_SECRET = 'bff-secret';
    private const REDIRECT = 'https://app.test/callback';
    private const START = 1_800_000_000_000;

    private static TestKey $key;

    private Clock $clock;
    private FakeTransport $idp;
    /** @var array<string, array{challenge: string, nonce: string, redirectUri: string, used: bool}> */
    private array $codes = [];
    /** @var array<string, array{family: string, used: bool}> */
    private array $refreshTokens = [];
    /** @var array<string, true> */
    private array $revokedFamilies = [];
    /** @var array{refresh: int, reuse: int, code: int, revoke: int} */
    private array $counters = ['refresh' => 0, 'reuse' => 0, 'code' => 0, 'revoke' => 0];
    private ?Request $lastTokenRequest = null;
    private ?Request $lastRevoke = null;
    /** @var array<string, mixed> */
    private array $meta = [];
    private ?\Closure $idTokenOverride = null;
    private ?\Closure $tokenOverride = null;

    public static function setUpBeforeClass(): void
    {
        self::$key = TestKey::make('ES256', 'idp-1');
    }

    protected function setUp(): void
    {
        $this->clock = new Clock(self::START);
        $this->meta = [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/oauth/authorize?tenant=main',
            'token_endpoint' => self::ISSUER . '/oauth/token',
            'jwks_uri' => self::ISSUER . '/jwks',
            'revocation_endpoint' => self::ISSUER . '/oauth/revoke',
            'end_session_endpoint' => self::ISSUER . '/oidc/logout',
            'authorization_response_iss_parameter_supported' => true,
        ];
        $this->idp = new FakeTransport(fn (Request $r): Response => $this->handle($r));
    }

    private function nowSec(): int
    {
        return intdiv((int) $this->clock->now, 1000);
    }

    private function idToken(array $claims, array $header = ['typ' => 'JWT'], ?TestKey $k = null): string
    {
        return Jwt::sign($k ?? self::$key, array_merge(['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => self::CLIENT_ID, 'iat' => $this->nowSec(), 'exp' => $this->nowSec() + 300], $claims), $header);
    }

    /** @return array<string, mixed> */
    private function issue(string $family, ?string $nonce = null): array
    {
        $at = 'pa_at_' . Jwt::b64(random_bytes(12));
        $rt = 'pa_rt_' . Jwt::b64(random_bytes(12));
        $this->refreshTokens[$rt] = ['family' => $family, 'used' => false];
        $id = null;
        if ($nonce !== null) {
            $id = $this->idTokenOverride !== null
                ? ($this->idTokenOverride)($nonce, $at)
                : $this->idToken(['nonce' => $nonce, 'at_hash' => Pkce::halfHash('ES256', $at), 'azp' => self::CLIENT_ID, 'sid' => 'ses_1', 'auth_time' => $this->nowSec() - 5]);
        }
        return ['access_token' => $at, 'token_type' => 'Bearer', 'expires_in' => 300, 'refresh_token' => $rt, 'scope' => 'openid orders:read'] + ($id !== null ? ['id_token' => $id] : []);
    }

    private function handle(Request $r): Response
    {
        $path = (string) parse_url($r->url, PHP_URL_PATH);
        $p = '/realms/main';
        if ($path === "{$p}/.well-known/openid-configuration") {
            return FakeTransport::json(200, $this->meta);
        }
        if ($path === "{$p}/jwks") {
            return FakeTransport::json(200, ['keys' => [self::$key->jwk]]);
        }
        if ($path === "{$p}/oauth/token" && $r->method === 'POST') {
            $this->lastTokenRequest = $r;
            if ($this->tokenOverride !== null) {
                return ($this->tokenOverride)($r);
            }
            $form = FakeTransport::form($r->body);
            if (($form['grant_type'] ?? '') === 'authorization_code') {
                $this->counters['code']++;
                $c = $this->codes[$form['code'] ?? ''] ?? null;
                if ($c === null || $c['used'] || Pkce::challenge($form['code_verifier'] ?? '') !== $c['challenge'] || ($form['redirect_uri'] ?? '') !== $c['redirectUri']) {
                    return FakeTransport::json(400, ['error' => 'invalid_grant']);
                }
                $this->codes[$form['code']]['used'] = true;
                return FakeTransport::json(200, $this->issue(bin2hex(random_bytes(4)), $c['nonce']), ['cache-control' => 'no-store']);
            }
            if (($form['grant_type'] ?? '') === 'refresh_token') {
                $this->counters['refresh']++;
                $rt = $this->refreshTokens[$form['refresh_token'] ?? ''] ?? null;
                if ($rt === null || isset($this->revokedFamilies[$rt['family']])) {
                    return FakeTransport::json(400, ['error' => 'invalid_grant']);
                }
                if ($rt['used']) {
                    $this->counters['reuse']++;
                    $this->revokedFamilies[$rt['family']] = true; // reuse revokes the whole family
                    return FakeTransport::json(400, ['error' => 'invalid_grant']);
                }
                $this->refreshTokens[$form['refresh_token']]['used'] = true;
                return FakeTransport::json(200, $this->issue($rt['family']));
            }
            return FakeTransport::json(400, ['error' => 'unsupported_grant_type']);
        }
        if ($path === "{$p}/oauth/revoke" && $r->method === 'POST') {
            $this->counters['revoke']++;
            $this->lastRevoke = $r;
            $rt = $this->refreshTokens[FakeTransport::form($r->body)['token'] ?? ''] ?? null;
            if ($rt !== null) {
                $this->revokedFamilies[$rt['family']] = true;
            }
            return new Response(200);
        }
        return FakeTransport::json(404, []);
    }

    /** @param array<string, mixed> $over */
    private function client(array $over = []): OidcClient
    {
        return new OidcClient(...array_merge([
            'issuer' => self::ISSUER,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT,
            'scopes' => ['openid', 'orders:read'],
            'resource' => 'https://api.test/orders',
            'now' => $this->clock->fn(),
            'jwksMinRefreshIntervalMs' => 60_000,
            'transport' => $this->idp,
        ], $over));
    }

    /**
     * Simulates the user completing login at the IdP.
     *
     * @return array{0: AuthRequest, 1: string, 2: string} the auth request, the code and the callback URL
     */
    private function login(OidcClient $c): array
    {
        $ar = $c->authorizationUrl();
        $q = Query::parse((string) parse_url($ar->url, PHP_URL_QUERY));
        $code = 'pa_ac_' . bin2hex(random_bytes(8));
        $this->codes[$code] = [
            'challenge' => $q->getAll('code_challenge')[0],
            'nonce' => $q->getAll('nonce')[0],
            'redirectUri' => $q->getAll('redirect_uri')[0],
            'used' => false,
        ];
        return [$ar, $code, self::REDIRECT . "?code={$code}&state={$ar->state}&iss=" . rawurlencode(self::ISSUER)];
    }

    /** @return array{0: OidcClient, 1: Session, 2: TokenSet, 3: \ArrayObject<int, string>} */
    private function loggedIn(): array
    {
        $c = $this->client();
        [$ar, , $callback] = $this->login($c);
        $res = $c->exchangeCode($ar, $callback);
        $persisted = new \ArrayObject();
        $s = $c->session($res->tokens, $res->idClaims, static function (TokenSet $t) use ($persisted): void {
            $persisted[] = (string) $t->refreshToken;
        });
        return [$c, $s, $res->tokens, $persisted];
    }

    public function testBuildsAnAuthorizationUrlWithPkceS256StateNonceAndResource(): void
    {
        $ar = $this->client()->authorizationUrl(['prompt' => 'login']);
        $u = parse_url($ar->url);
        self::assertSame(self::ISSUER . '/oauth/authorize', "{$u['scheme']}://{$u['host']}{$u['path']}");
        $q = Query::parse($u['query']);
        self::assertSame(['main'], $q->getAll('tenant'), 'existing endpoint parameters are kept');
        self::assertSame(['code'], $q->getAll('response_type'));
        self::assertSame([self::CLIENT_ID], $q->getAll('client_id'));
        self::assertSame([self::REDIRECT], $q->getAll('redirect_uri'));
        self::assertSame(['openid orders:read'], $q->getAll('scope'));
        self::assertSame([$ar->state], $q->getAll('state'));
        self::assertSame([$ar->nonce], $q->getAll('nonce'));
        self::assertSame(['S256'], $q->getAll('code_challenge_method'));
        self::assertSame([rtrim(strtr(base64_encode(hash('sha256', $ar->codeVerifier, true)), '+/', '-_'), '=')], $q->getAll('code_challenge'));
        self::assertSame(['https://api.test/orders'], $q->getAll('resource'));
        self::assertSame(['login'], $q->getAll('prompt'));
        self::assertStringContains('scope=openid+orders%3Aread', $ar->url);
        self::assertTrue(strlen($ar->codeVerifier) >= 43 && strlen($ar->state) >= 43 && strlen($ar->nonce) >= 43);
        self::assertNotSame($ar->state, $ar->nonce);
        self::assertSame(self::START, $ar->createdAt);
        $custom = $this->client()->authorizationUrl(null, ['openid'], '');
        self::assertStringNotContains('resource=', $custom->url);
        self::assertSame(['openid'], $custom->scopes);
    }

    public function testRefusesToOverrideSecurityParametersThroughExtraParams(): void
    {
        foreach (['state', 'nonce', 'code_challenge', 'code_challenge_method', 'redirect_uri', 'client_id', 'response_type', 'scope', 'resource', 'request', 'request_uri'] as $k) {
            self::assertThrows(\InvalidArgumentException::class, fn () => $this->client()->authorizationUrl([$k => 'x']), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'cannot be set'), $k);
        }
    }

    public function testExchangesTheCodeValidatingStateIssNonceAndAtHash(): void
    {
        $c = $this->client();
        [$ar, , $callback] = $this->login($c);
        $res = $c->exchangeCode($ar, $callback);
        self::assertTrue(str_starts_with($res->tokens->accessToken, 'pa_at_'));
        self::assertTrue(str_starts_with((string) $res->tokens->refreshToken, 'pa_rt_'));
        self::assertSame(self::START + 300_000, $res->tokens->expiresAt);
        self::assertSame('usr_1', $res->idClaims?->subject);
        self::assertSame($ar->nonce, $res->idClaims?->nonce);
        self::assertSame('ses_1', $res->idClaims?->sid);
        self::assertSame(self::CLIENT_ID, $res->idClaims?->azp);
        self::assertSame($ar->nonce, $res->idClaims?->claims['nonce']);
        $form = FakeTransport::form($this->lastTokenRequest?->body);
        self::assertSame($ar->codeVerifier, $form['code_verifier']);
        self::assertSame(self::REDIRECT, $form['redirect_uri']);
        self::assertSame('Basic ' . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET), $this->lastTokenRequest?->header('authorization'));
        self::assertTrue(!isset($form['client_secret']) && !isset($form['client_id']));
    }

    public function testAcceptsTheCallbackAsRequestUriOrParameters(): void
    {
        $c = $this->client();
        [$ar, $code] = $this->login($c);
        $c->exchangeCode($ar, "/callback?code={$code}&state={$ar->state}&iss=" . rawurlencode(self::ISSUER));
        [$ar2, $code2] = $this->login($c);
        $c->exchangeCode($ar2, ['code' => $code2, 'state' => $ar2->state, 'iss' => self::ISSUER]);
        [$ar3, $code3] = $this->login($c);
        $c->exchangeCode(AuthRequest::fromArray($ar3->toArray()), "code={$code3}&state={$ar3->state}&iss=" . rawurlencode(self::ISSUER));
        self::assertSame(3, $this->counters['code']);
    }

    public function testRejectsAStateMismatchBeforeRedeemingTheCode(): void
    {
        $c = $this->client();
        [$ar, $code] = $this->login($c);
        $before = $this->counters['code'];
        self::assertOidcError(O::State, static fn () => $c->exchangeCode($ar, ['code' => $code, 'state' => 'attacker', 'iss' => self::ISSUER]));
        self::assertOidcError(O::State, static fn () => $c->exchangeCode($ar, ['code' => $code, 'iss' => self::ISSUER]));
        self::assertOidcError(O::State, static fn () => $c->exchangeCode($ar, ['code' => $code, 'state' => '', 'iss' => self::ISSUER]));
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, "?code={$code}&state={$ar->state}&state=other&iss=" . rawurlencode(self::ISSUER)), 'duplicate state parameter');
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, ['code' => $code, 'state' => [$ar->state, 'x'], 'iss' => self::ISSUER]), 'duplicate state parameter');
        self::assertSame($before, $this->counters['code']);
    }

    public function testRejectsMixUpWrongOrMissingIssInTheAuthorizationResponse(): void
    {
        $c = $this->client();
        [$ar, $code] = $this->login($c);
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, ['code' => $code, 'state' => $ar->state, 'iss' => 'https://evil.test']), 'authorization response issuer mismatch (mix-up)');
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, ['code' => $code, 'state' => $ar->state]), 'authorization response is missing iss');
        $this->meta['authorization_response_iss_parameter_supported'] = false;
        $c2 = $this->client();
        [$ar2, $code2] = $this->login($c2);
        $c2->exchangeCode($ar2, ['code' => $code2, 'state' => $ar2->state]); // iss optional when not advertised
    }

    public function testSurfacesProviderErrorsWithoutEchoingArbitraryText(): void
    {
        $c = $this->client();
        [$ar] = $this->login($c);
        $e = self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, ['error' => 'access_denied', 'state' => $ar->state, 'iss' => self::ISSUER]));
        self::assertSame('access_denied', $e->providerError);
        $e = self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, ['error' => '<script>', 'state' => $ar->state, 'iss' => self::ISSUER]));
        self::assertSame('unrecognized_error', $e->providerError);
        self::assertStringNotContains('<script>', $e->getMessage());
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, ['state' => $ar->state, 'iss' => self::ISSUER]), 'missing authorization code');
    }

    public function testMapsAReplayedCodeToReauthenticate(): void
    {
        $c = $this->client();
        [$ar, , $callback] = $this->login($c);
        $c->exchangeCode($ar, $callback);
        $e = self::assertOidcError(O::Reauthenticate, static fn () => $c->exchangeCode($ar, $callback));
        self::assertSame('invalid_grant', $e->providerError);
        self::assertSame(400, $e->status);
        self::assertSame('oidc-client: refresh failed; the user must authenticate again (invalid_grant, HTTP 400)', $e->getMessage());
    }

    public function testRejectsANonceMismatchAndABadAtHash(): void
    {
        $c = $this->client();
        $this->idTokenOverride = fn (string $nonce, string $at): string => $this->idToken(['nonce' => 'other', 'at_hash' => Pkce::halfHash('ES256', $at)]);
        [$ar1, , $cb1] = $this->login($c);
        self::assertOidcError(O::Nonce, static fn () => $c->exchangeCode($ar1, $cb1));
        $this->idTokenOverride = fn (string $nonce): string => $this->idToken(['nonce' => $nonce, 'at_hash' => Pkce::halfHash('ES256', 'different-token')]);
        [$ar2, , $cb2] = $this->login($c);
        self::assertOidcError(O::IdToken, static fn () => $c->exchangeCode($ar2, $cb2), 'at_hash');
        $this->idTokenOverride = static fn (): ?string => null;
        // An openid request must return an ID token.
        [$ar3, , $cb3] = $this->login($c);
        self::assertOidcError(O::IdToken, static fn () => $c->exchangeCode($ar3, $cb3), 'missing ID token');
    }

    public function testAcceptsAValidIdToken(): void
    {
        $claims = $this->client()->validateIdToken($this->idToken(['nonce' => 'n1', 'amr' => ['pwd', 7, 'otp'], 'email' => 'a@example.test', 'name' => 'Ann', 'acr' => 'mfa']), nonce: 'n1');
        self::assertSame(self::ISSUER, $claims->issuer);
        self::assertSame([self::CLIENT_ID], $claims->audience);
        self::assertSame(['pwd', 'otp'], $claims->amr);
        self::assertSame('a@example.test', $claims->email);
        self::assertSame('Ann', $claims->name);
        self::assertSame('mfa', $claims->acr);
        self::assertSame($this->nowSec() + 300, $claims->expiry->getTimestamp());
    }

    public function testRejectsWrongIssuerAudienceAzpExpiryIatAndSubject(): void
    {
        $c = $this->client();
        $now = $this->nowSec();
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['iss' => 'https://evil.test'])), 'issuer');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['aud' => 'other-client'])), 'audience');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['aud' => null])), 'audience');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['aud' => [self::CLIENT_ID, 'other']])), 'authorized party');
        $c->validateIdToken($this->idToken(['aud' => [self::CLIENT_ID, 'other'], 'azp' => self::CLIENT_ID]));
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['azp' => 'other'])), 'authorized party');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['exp' => $now - 31])), 'expired');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['exp' => null])), 'expired');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['iat' => $now + 120])), 'issued in the future');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['sub' => ''])), 'subject');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['sub' => 42])), 'claim sub');
        self::assertOidcError(O::Nonce, fn () => $c->validateIdToken($this->idToken(['nonce' => 'a']), nonce: 'b'));
        self::assertOidcError(O::Nonce, fn () => $c->validateIdToken($this->idToken([]), nonce: 'b'));
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken(['auth_time' => $now - 600]), maxAgeSec: 300), 'max_age');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken([]), maxAgeSec: 300), 'max_age');
        $c->validateIdToken($this->idToken(['auth_time' => $now - 200]), maxAgeSec: 300);
    }

    public function testRejectsAlgNoneHs256ConfusionAccessTokensAndForeignKeys(): void
    {
        $c = $this->client();
        $payload = ['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => self::CLIENT_ID, 'exp' => $this->nowSec() + 60];
        $none = Jwt::b64(Jwt::encode(['alg' => 'none', 'kid' => self::$key->kid])) . '.' . Jwt::b64(Jwt::encode($payload)) . '.';
        self::assertOidcError(O::IdToken, static fn () => $c->validateIdToken($none), 'algorithm');
        $input = Jwt::b64(Jwt::encode(['alg' => 'HS256', 'kid' => self::$key->kid])) . '.' . Jwt::b64(Jwt::encode($payload));
        $hs = $input . '.' . Jwt::b64(hash_hmac('sha256', $input, Jwt::encode(self::$key->jwk), true));
        self::assertOidcError(O::IdToken, static fn () => $c->validateIdToken($hs), 'algorithm');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken([], ['typ' => 'at+jwt'])), 'type');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken([], ['typ' => 'JWT'], TestKey::make('ES256', self::$key->kid))), 'signature');
        $dup = Jwt::signRaw(self::$key, Jwt::encode(['alg' => 'ES256', 'kid' => self::$key->kid]), substr(Jwt::encode($payload), 0, -1) . ',"sub":"usr_admin"}');
        self::assertOidcError(O::IdToken, static fn () => $c->validateIdToken($dup), 'duplicate member');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken([], ['typ' => 'JWT', 'crit' => ['exp']])), 'critical header');
        self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken([], ['typ' => 'JWT', 'kid' => null])), 'missing kid');
        self::assertOidcError(O::IdToken, static fn () => $c->validateIdToken('a.b'), 'malformed');
        self::assertOidcError(O::IdToken, static fn () => $c->validateIdToken(''), 'size');
        self::assertOidcError(O::IdToken, static fn () => $c->validateIdToken(str_repeat('a', 16385)), 'size');
        $c->validateIdToken($this->idToken([], ['typ' => null])); // typ is optional for ID tokens
    }

    public function testBoundsJwksFetchesForUnknownKeyIds(): void
    {
        $c = $this->client();
        for ($i = 0; $i < 100; $i++) {
            self::assertOidcError(O::IdToken, fn () => $c->validateIdToken($this->idToken([], ['typ' => 'JWT', 'kid' => bin2hex(random_bytes(6))])), 'unknown key');
        }
        self::assertSame(1, $c->jwksFetchCount());
    }

    public function testSharesTheIdTokenKeySetThroughAStore(): void
    {
        $store = new MemoryStore();
        $this->client(['cache' => $store])->validateIdToken($this->idToken([]));
        $c2 = $this->client(['cache' => $store]);
        $c2->validateIdToken($this->idToken([]));
        self::assertSame(0, $c2->jwksFetchCount());
    }

    public function testReturnsTheCurrentTokenWhileItIsFresh(): void
    {
        [, $s, $tokens] = $this->loggedIn();
        self::assertSame($tokens->accessToken, $s->accessToken());
        self::assertSame(0, $s->refreshCount());
    }

    public function testRefreshesOnceNearExpiryAndSurvivesRotation(): void
    {
        [, $s, $tokens, $persisted] = $this->loggedIn();
        $before = $this->counters;
        $this->clock->now += 290_000; // inside the 15 s refresh window
        $results = [];
        for ($i = 0; $i < 25; $i++) {
            $results[] = $s->accessToken();
        }
        self::assertCount(1, array_unique($results));
        self::assertNotSame($tokens->accessToken, $results[0]);
        self::assertSame(1, $this->counters['refresh'] - $before['refresh']);
        self::assertSame(1, $s->refreshCount());
        self::assertNotSame($tokens->refreshToken, $s->tokens()?->refreshToken, 'refresh token rotated');
        self::assertCount(1, $persisted->getArrayCopy());
        // A second expiry: the rotated token is used; no reuse, family intact.
        $this->clock->now += 300_000;
        $again = [];
        for ($i = 0; $i < 25; $i++) {
            $again[] = $s->accessToken();
        }
        self::assertCount(1, array_unique($again));
        self::assertSame(2, $this->counters['refresh'] - $before['refresh']);
        self::assertSame(0, $this->counters['reuse'] - $before['reuse']);
        self::assertSame($tokens->idToken, $s->tokens()?->idToken, 'ID token kept when not reissued');
    }

    public function testParallelUseOfOneRefreshTokenRevokesTheFamily(): void
    {
        // Two PHP workers each holding the same stored tokens, without a lock.
        [$c, , $tokens] = $this->loggedIn();
        $a = $c->session($tokens);
        $b = $c->session($tokens);
        $this->clock->now += 300_000;
        $a->accessToken();
        self::assertOidcError(O::Reauthenticate, static fn () => $b->accessToken());
        self::assertSame(1, $this->counters['reuse']);
        $this->clock->now += 300_000;
        self::assertOidcError(O::Reauthenticate, static fn () => $a->accessToken()); // family revoked after reuse
    }

    public function testALockWithReloadPreventsRefreshTokenReuseAcrossWorkers(): void
    {
        $dir = sys_get_temp_dir() . '/proudauth-php-lock-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        try {
            [$c, , $tokens] = $this->loggedIn();
            $stored = $tokens->toArray(); // the application's server-side session storage
            $locks = new FileRefreshLock($dir);
            $worker = function () use ($c, &$stored, $locks): Session {
                return $c->session(
                    TokenSet::fromArray($stored),
                    onRefresh: static function (TokenSet $t) use (&$stored): void {
                        $stored = $t->toArray();
                    },
                    lock: $locks->for('sid-1'),
                    reload: static function () use (&$stored): ?TokenSet {
                        return $stored === null ? null : TokenSet::fromArray($stored);
                    },
                );
            };
            $a = $worker();
            $b = $worker(); // started before $a refreshed: holds the old tokens
            $this->clock->now += 300_000;
            $ta = $a->accessToken();
            $tb = $b->accessToken();
            self::assertSame($ta, $tb, 'the second worker picks up the rotated tokens');
            self::assertSame(1, $this->counters['refresh']);
            self::assertSame(0, $this->counters['reuse']);
            self::assertSame(0, $b->refreshCount());
            $stored = null; // logged out elsewhere
            $this->clock->now += 300_000;
            self::assertOidcError(O::Reauthenticate, static fn () => $b->accessToken());
            self::assertCount(1, glob($dir . '/proudauth-refresh-*.lock') ?: []);
        } finally {
            array_map('unlink', glob($dir . '/*') ?: []);
            rmdir($dir);
        }
    }

    public function testFileRefreshLockIsExclusive(): void
    {
        $dir = sys_get_temp_dir() . '/proudauth-php-lock-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        try {
            $locks = new FileRefreshLock($dir);
            $result = $locks->synchronized('sid-2', static function () use ($dir): string {
                $files = glob($dir . '/proudauth-refresh-*.lock') ?: [];
                $fh = fopen($files[0], 'c');
                $other = flock($fh, LOCK_EX | LOCK_NB);
                fclose($fh);
                return $other ? 'not exclusive' : 'exclusive';
            });
            self::assertSame('exclusive', $result);
            $files = glob($dir . '/proudauth-refresh-*.lock') ?: [];
            $fh = fopen($files[0], 'c');
            self::assertTrue(flock($fh, LOCK_EX | LOCK_NB), 'released afterwards');
            fclose($fh);
            self::assertThrows(\RuntimeException::class, static fn () => $locks->synchronized('sid-3', static fn () => throw new \RuntimeException('inner')));
            self::assertThrows(\InvalidArgumentException::class, static fn () => new FileRefreshLock($dir . '/missing'));
        } finally {
            array_map('unlink', glob($dir . '/*') ?: []);
            rmdir($dir);
        }
    }

    public function testForcesOneRefreshForARejectedAccessToken(): void
    {
        [, $s, $tokens] = $this->loggedIn();
        $x = $s->accessToken($tokens->accessToken);
        $y = $s->accessToken($tokens->accessToken);
        self::assertSame($x, $y);
        self::assertNotSame($tokens->accessToken, $x);
        self::assertSame(1, $s->refreshCount(), 'a stale rejection does not refresh again');
    }

    public function testClearsTheSessionWhenRefreshFails(): void
    {
        [$c, $s, $tokens] = $this->loggedIn();
        $c->revoke((string) $tokens->refreshToken);
        $this->clock->now += 300_000;
        self::assertOidcError(O::Reauthenticate, static fn () => $s->accessToken());
        self::assertNull($s->tokens());
        $before = $this->counters['refresh'];
        self::assertOidcError(O::Reauthenticate, static fn () => $s->accessToken());
        self::assertSame($before, $this->counters['refresh'], 'no further provider calls');
        $noRefresh = $c->session(new TokenSet('at', 'Bearer', 300, null, null, null, self::START));
        self::assertOidcError(O::Reauthenticate, static fn () => $noRefresh->accessToken());
    }

    public function testRejectsARefreshedIdTokenForAnotherSubject(): void
    {
        [$c, $s] = $this->loggedIn();
        $this->tokenOverride = fn (): Response => FakeTransport::json(200, ['access_token' => 'pa_at_new', 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $this->idToken(['sub' => 'usr_2'])]);
        $this->clock->now += 300_000;
        $e = self::assertOidcError(O::Reauthenticate, static fn () => $s->accessToken(), 'id_token');
        self::assertInstanceOf(OidcException::class, $e->getPrevious());
        self::assertNull($s->tokens());
    }

    public function testRevokesWithClientAuthenticationAndBuildsTheLogoutUrl(): void
    {
        $c = $this->client();
        [$ar, , $callback] = $this->login($c);
        $res = $c->exchangeCode($ar, $callback);
        $s = $c->session($res->tokens, $res->idClaims);
        $url = $c->logout($s, 'https://app.test/bye', 'st');
        $u = parse_url($url);
        self::assertSame(self::ISSUER . '/oidc/logout', "{$u['scheme']}://{$u['host']}{$u['path']}");
        $q = Query::parse($u['query']);
        self::assertSame([$res->tokens->idToken], $q->getAll('id_token_hint'));
        self::assertSame([self::CLIENT_ID], $q->getAll('client_id'));
        self::assertSame(['https://app.test/bye'], $q->getAll('post_logout_redirect_uri'));
        self::assertSame(['st'], $q->getAll('state'));
        self::assertNull($s->tokens());
        $form = FakeTransport::form($this->lastRevoke?->body);
        self::assertSame($res->tokens->refreshToken, $form['token']);
        self::assertSame('refresh_token', $form['token_type_hint']);
        self::assertTrue(str_starts_with((string) $this->lastRevoke?->header('authorization'), 'Basic '));
        self::assertSame(self::ISSUER . '/oidc/logout?client_id=' . self::CLIENT_ID, $c->logoutUrl());
    }

    public function testReportsRevocationFailures(): void
    {
        $c = $this->client();
        $c->revoke(''); // nothing to revoke
        self::assertSame(0, $this->counters['revoke']);
        $this->meta['revocation_endpoint'] = self::ISSUER . '/oauth/missing';
        self::assertOidcError(O::Provider, fn () => $this->client()->revoke('x'), 'revocation failed');
    }

    public function testSendsClientIdInTheBodyForPublicClients(): void
    {
        $c = $this->client(['clientSecret' => '']);
        [$ar, , $callback] = $this->login($c);
        $c->exchangeCode($ar, $callback);
        self::assertNull($this->lastTokenRequest?->header('authorization'));
        self::assertSame(self::CLIENT_ID, FakeTransport::form($this->lastTokenRequest?->body)['client_id']);
    }

    public function testValidatesTokenEndpointResponses(): void
    {
        $cases = [
            'invalid token response' => static fn (): Response => FakeTransport::json(200, 'not json'),
            'missing access_token' => static fn (): Response => FakeTransport::json(200, ['token_type' => 'Bearer']),
            'unsupported token_type' => static fn (): Response => FakeTransport::json(200, ['access_token' => 'a', 'token_type' => 'mac']),
            'invalid expires_in' => static fn (): Response => FakeTransport::json(200, ['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => -1]),
            'token endpoint error' => static fn (): Response => FakeTransport::json(401, ['error' => 'invalid_client']),
        ];
        foreach ($cases as $reason => $handler) {
            $this->tokenOverride = $handler;
            $c = $this->client();
            [$ar, , $callback] = $this->login($c);
            self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, $callback), $reason, $reason);
        }
        $this->tokenOverride = static fn (): Response => FakeTransport::json(200, ['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => null]);
        $c = $this->client();
        [$ar, , $callback] = $this->login($c);
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, $callback), 'invalid expires_in');
        $this->tokenOverride = static fn (): Response => FakeTransport::json(401, ['error' => 'invalid_client']);
        $e = self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, $callback));
        self::assertSame('invalid_client', $e->providerError);
        self::assertSame(401, $e->status);
        $this->tokenOverride = static fn (): Response => FakeTransport::json(200, ['access_token' => 'a', 'token_type' => 'bearer']);
        $c = $this->client(['scopes' => ['orders:read']]);
        [$ar, , $callback] = $this->login($c);
        $res = $c->exchangeCode($ar, $callback);
        self::assertNull($res->idClaims, 'no ID token is required without openid');
        self::assertSame(0, $res->tokens->expiresIn);
    }

    public function testTrustsOnlyDiscoveryFromTheConfiguredIssuerWithEndpointsOnItsOrigin(): void
    {
        $this->meta['issuer'] = 'https://evil.test/realms/main';
        self::assertOidcError(O::Provider, fn () => $this->client()->authorizationUrl(), 'discovery issuer mismatch');
        $this->meta['issuer'] = self::ISSUER;
        $this->meta['token_endpoint'] = 'https://evil.test/token';
        $c = $this->client();
        [$ar, , $callback] = $this->login($c);
        self::assertOidcError(O::Provider, static fn () => $c->exchangeCode($ar, $callback), 'endpoint token_endpoint is not on the issuer origin');
        foreach (['https://idp.test.evil.test/token', 'https://idp.test:444/token', 'http://idp.test/token', 'https://user@idp.test/token', 'ftp://idp.test/token'] as $ep) {
            $this->meta['token_endpoint'] = $ep;
            $c2 = $this->client();
            [$ar2, , $cb2] = $this->login($c2);
            self::assertOidcError(O::Provider, static fn () => $c2->exchangeCode($ar2, $cb2), 'endpoint token_endpoint is not on the issuer origin', $ep);
        }
        $this->meta['token_endpoint'] = 'not a url';
        $c3 = $this->client();
        [$ar3, , $cb3] = $this->login($c3);
        self::assertOidcError(O::Provider, static fn () => $c3->exchangeCode($ar3, $cb3), 'invalid endpoint token_endpoint');
        unset($this->meta['token_endpoint']);
        $c4 = $this->client();
        [$ar4, , $cb4] = $this->login($c4);
        self::assertOidcError(O::Provider, static fn () => $c4->exchangeCode($ar4, $cb4), 'missing endpoint token_endpoint');
        $this->meta['token_endpoint'] = 'HTTPS://IDP.TEST:443/realms/main/oauth/token';
        $c5 = $this->client();
        [$ar5, , $cb5] = $this->login($c5);
        $c5->exchangeCode($ar5, $cb5); // same origin, other spelling
    }

    public function testRetriesDiscoveryAfterAFailure(): void
    {
        $fail = true;
        $t = new FakeTransport(function (Request $r) use (&$fail): Response {
            if ($fail) {
                return FakeTransport::json(503, []);
            }
            return $this->handle($r);
        });
        $c = $this->client(['transport' => $t]);
        self::assertOidcError(O::Provider, static fn () => $c->discover(), 'metadata request failed');
        $fail = false;
        self::assertSame(self::ISSUER, $c->discover()['issuer']);
        $c->discover();
        self::assertSame(2, $t->hits(), 'a successful discovery is cached');
    }

    public function testValidatesConfiguration(): void
    {
        $has = static fn (string $part): \Closure => static fn (\Throwable $e): bool => str_contains($e->getMessage(), $part);
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->client(['issuer' => '']), $has('required'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->client(['redirectUri' => '']), $has('required'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->client(['redirectUri' => 'app://cb']), $has('http'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->client(['algorithms' => ['HS256']]), $has('not allowed'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->client(['clockSkewMs' => 120_000]), $has('60s'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->client(['jwksMinRefreshIntervalMs' => 10]), $has('at least 1000'));
        self::assertStringNotContains(self::CLIENT_SECRET, print_r($this->client(), true));
    }

    public function testStorageHelpersRoundTripAndHideTokens(): void
    {
        [, , $tokens] = $this->loggedIn();
        $copy = TokenSet::fromArray(json_decode(json_encode($tokens->toArray(), JSON_THROW_ON_ERROR), true));
        self::assertSame($tokens->toArray(), $copy->toArray());
        $dump = print_r($tokens, true);
        self::assertStringNotContains($tokens->accessToken, $dump);
        self::assertStringNotContains((string) $tokens->refreshToken, $dump);
        self::assertThrows(\InvalidArgumentException::class, static fn () => TokenSet::fromArray(['access_token' => '']));
        $ar = $this->client()->authorizationUrl();
        self::assertStringNotContains($ar->codeVerifier, print_r($ar, true));
        self::assertSame($ar->toArray(), AuthRequest::fromArray($ar->toArray())->toArray());
        self::assertThrows(\InvalidArgumentException::class, static fn () => AuthRequest::fromArray(['state' => 'x']));
        $restored = unserialize(serialize($tokens));
        self::assertSame($tokens->toArray(), $restored->toArray());
    }

    public function testHalfHashUsesSha512ForEdDsa(): void
    {
        self::assertSame(rtrim(strtr(base64_encode(substr(hash('sha512', 'at', true), 0, 32)), '+/', '-_'), '='), Pkce::halfHash('EdDSA', 'at'));
        self::assertSame(rtrim(strtr(base64_encode(substr(hash('sha256', 'at', true), 0, 16)), '+/', '-_'), '='), Pkce::halfHash('RS256', 'at'));
        // RFC 7636 appendix B.
        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Pkce::challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
        self::assertSame(43, strlen(Pkce::randomValue()));
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Cache\FileStore;
use ProudAuth\Sdk\Cache\MemoryStore;
use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Internal\Jose\Der;
use ProudAuth\Sdk\Tests\Support\Clock;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Tests\Support\Jwt;
use ProudAuth\Sdk\Tests\Support\TestKey;
use ProudAuth\Sdk\Verifier\Verifier;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Port of sdk/node/test/verifier.test.ts.
 */
final class VerifierTest extends TestCase
{
    private const ISS = 'https://id.test/realms/main';
    private const AUD = 'https://api.test/orders';
    private const JWKS = 'https://id.test/realms/main/jwks';
    private const NOW = 1_800_000_000; // seconds

    private static TestKey $es;
    private static TestKey $rs;
    private static TestKey $ps;
    private static TestKey $ed;
    /** @var list<array<string, mixed>> */
    private static array $published = [];
    private static int $status = 200;

    public static function setUpBeforeClass(): void
    {
        self::$es = TestKey::make('ES256', 'es-1');
        self::$rs = TestKey::make('RS256', 'rs-1');
        self::$ps = TestKey::make('PS256', 'ps-1');
        self::$ed = TestKey::make('EdDSA', 'ed-1');
    }

    protected function setUp(): void
    {
        self::$published = [self::$es->jwk, self::$rs->jwk, self::$ps->jwk, self::$ed->jwk];
        self::$status = 200;
    }

    private static function jwksServer(): FakeTransport
    {
        return new FakeTransport(static function (Request $r): Response {
            if (self::$status !== 200) {
                return FakeTransport::json(self::$status, ['error' => 'down']);
            }
            return FakeTransport::json(200, ['keys' => self::$published]);
        });
    }

    /** @param array<string, mixed> $over */
    private static function make(array $over = [], ?Clock $clock = null, ?FakeTransport &$transport = null): Verifier
    {
        $clock ??= new Clock(self::NOW * 1000);
        $transport ??= self::jwksServer();
        return new Verifier(...array_merge([
            'issuer' => self::ISS,
            'audience' => self::AUD,
            'jwksUrl' => self::JWKS,
            'now' => $clock->fn(),
            'minRefreshIntervalMs' => 60_000,
            'transport' => $transport,
        ], $over));
    }

    /** @return array<string, mixed> */
    private static function claims(array $extra = []): array
    {
        return array_merge([
            'iss' => self::ISS,
            'sub' => 'usr_1',
            'aud' => self::AUD,
            'client_id' => 'customer-web-bff',
            'iat' => self::NOW,
            'exp' => self::NOW + 300,
            'jti' => 'tok_' . bin2hex(random_bytes(6)),
            'sid' => 'ses_1',
            'scope' => 'orders:read orders:create',
            'org_id' => 'org_a',
            'token_kind' => 'user_access',
            'authz_version' => 43,
        ], $extra);
    }

    private static function rejects(E $code, Verifier $v, string $token, string $message = ''): void
    {
        self::assertVerifierError($code, static fn () => $v->verify($token), $message);
    }

    public function testAcceptsAValidTokenForEveryAllowlistedAlgorithm(): void
    {
        $v = self::make();
        foreach ([self::$es, self::$rs, self::$ps, self::$ed] as $k) {
            $c = $v->verify(Jwt::sign($k, self::claims()));
            self::assertSame('usr_1', $c->subject, $k->alg);
            self::assertSame(self::AUD, $c->audience);
            self::assertSame('customer-web-bff', $c->clientId);
            self::assertSame(['orders:read', 'orders:create'], $c->scopes);
            self::assertSame('org_a', $c->orgId);
            self::assertSame('ses_1', $c->sessionId);
            self::assertSame('user_access', $c->tokenKind);
            self::assertSame(43, $c->authzVersion);
            self::assertFalse($c->online);
            self::assertSame((self::NOW + 300) * 1000, $c->expiry?->getTimestamp() * 1000);
            self::assertSame(self::NOW, $c->issuedAt?->getTimestamp());
            self::assertSame('UTC', $c->expiry->getTimezone()->getName());
            self::assertThrows(\Error::class, static function () use ($c): void {
                $c->subject = 'usr_admin'; // @phpstan-ignore-line readonly
            });
        }
        self::assertSame(1, $v->fetchCount(), 'keys are cached');
    }

    public function testAcceptsApplicationAtJwtAndACaseInsensitiveTyp(): void
    {
        $v = self::make();
        $v->verify(Jwt::sign(self::$es, self::claims(), ['typ' => 'application/at+jwt']));
        $v->verify(Jwt::sign(self::$es, self::claims(), ['typ' => 'AT+JWT']));
        self::assertSame(1, $v->fetchCount());
    }

    public function testAcceptsTheAudienceAsASingleElementArray(): void
    {
        self::assertSame(self::AUD, self::make()->verify(Jwt::sign(self::$es, self::claims(['aud' => [self::AUD]])))->audience);
    }

    public function testPreservesTheActorOfExchangedTokens(): void
    {
        $c = self::make()->verify(Jwt::sign(self::$es, self::claims([
            'token_kind' => 'exchange_access',
            'act' => ['sub' => 'svc_orders', 'iss' => self::ISS, 'act' => ['sub' => 'svc_gw']],
        ])));
        self::assertSame('svc_orders', $c->actor?->subject);
        self::assertSame(self::ISS, $c->actor?->issuer);
        self::assertSame('svc_gw', $c->actor?->act?->subject);
        self::assertNull($c->actor?->act?->issuer);
    }

    public function testRejectsATokenFromAnotherIssuerWithoutFetchingKeys(): void
    {
        $v = self::make();
        self::rejects(E::Issuer, $v, Jwt::sign(self::$es, self::claims(['iss' => 'https://evil.test/realms/main'])));
        self::rejects(E::Issuer, $v, Jwt::sign(self::$es, self::claims(['iss' => self::ISS . '/'])));
        self::rejects(E::Issuer, $v, Jwt::sign(self::$es, self::claims(['iss' => null])));
        self::rejects(E::Issuer, $v, Jwt::sign(self::$es, self::claims(['iss' => [self::ISS]])));
        self::assertSame(0, $v->fetchCount());
    }

    public function testNeverFetchesUrlsFromJkuX5uOrJwkHeaders(): void
    {
        $evil = TestKey::make('ES256', 'evil');
        $t = null;
        $v = self::make([], null, $t);
        $tok = Jwt::sign($evil, self::claims(), ['jku' => 'https://attacker.test/jwks', 'x5u' => 'https://attacker.test/cert', 'jwk' => $evil->jwk]);
        self::rejects(E::UnknownKey, $v, $tok);
        self::assertTrue($t->hits() > 0);
        foreach ($t->requests as $r) {
            self::assertSame(self::JWKS, $r->url, 'only the configured key set is fetched');
            self::assertSame('GET', $r->method);
        }
    }

    public function testRejectsTheWrongAudience(): void
    {
        $v = self::make();
        self::rejects(E::Audience, $v, Jwt::sign(self::$es, self::claims(['aud' => 'https://api.test/billing'])));
        self::rejects(E::Audience, $v, Jwt::sign(self::$es, self::claims(['aud' => [self::AUD, 'https://api.test/billing']])));
        self::rejects(E::Audience, $v, Jwt::sign(self::$es, self::claims(['aud' => []])));
        self::rejects(E::Audience, $v, Jwt::sign(self::$es, self::claims(['aud' => null])));
        self::rejects(E::Audience, $v, Jwt::sign(self::$es, self::claims(['aud' => self::AUD . '/'])));
    }

    public function testRejectsAlgNoneWithoutFetching(): void
    {
        $v = self::make();
        foreach (['none', 'None', 'NONE'] as $alg) {
            $tok = Jwt::b64(Jwt::encode(['alg' => $alg, 'typ' => 'at+jwt', 'kid' => self::$es->kid])) . '.' . Jwt::b64(Jwt::encode(self::claims())) . '.';
            self::rejects(E::Algorithm, $v, $tok, $alg);
        }
        self::assertSame(0, $v->fetchCount());
    }

    public function testRejectsHs256SignedWithThePublicKeyAsTheHmacSecret(): void
    {
        $v = self::make();
        $pem = Der::pem(Der::rsaSpki(
            (string) base64_decode(strtr(self::$rs->jwk['n'], '-_', '+/')),
            (string) base64_decode(strtr(self::$rs->jwk['e'], '-_', '+/')),
        ));
        foreach ([Jwt::encode(self::$rs->jwk), $pem] as $secret) {
            $input = Jwt::b64(Jwt::encode(['alg' => 'HS256', 'typ' => 'at+jwt', 'kid' => self::$rs->kid])) . '.' . Jwt::b64(Jwt::encode(self::claims()));
            self::rejects(E::Algorithm, $v, $input . '.' . Jwt::b64(hash_hmac('sha256', $input, $secret, true)));
        }
        self::assertSame(0, $v->fetchCount());
    }

    public function testRefusesSymmetricUnsignedAndUnsupportedAlgorithmsInConfiguration(): void
    {
        $not = static fn (\InvalidArgumentException $e): bool => str_contains($e->getMessage(), 'not allowed');
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['algorithms' => ['HS256']]), $not);
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['algorithms' => ['none']]), $not);
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['algorithms' => ['RS256', 'hs512']]), $not);
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['algorithms' => ['ES512']]), static fn (\InvalidArgumentException $e): bool => str_contains($e->getMessage(), 'not supported'));
    }

    public function testRejectsAnAlgorithmOutsideANarrowedAllowlist(): void
    {
        $v = self::make(['algorithms' => ['ES256']]);
        $v->verify(Jwt::sign(self::$es, self::claims()));
        self::rejects(E::Algorithm, $v, Jwt::sign(self::$rs, self::claims()));
    }

    public function testRejectsAKeyWhoseJwkAlgDiffersFromTheTokenAlg(): void
    {
        // rs.jwk declares alg RS256; a PS256 token signed with the same RSA key is refused.
        $tok = Jwt::sign(self::$rs->asAlg('PS256'), self::claims(), ['alg' => 'PS256', 'kid' => self::$rs->kid]);
        self::rejects(E::Algorithm, self::make(), $tok);
    }

    public function testRejectsKeyTypeConfusion(): void
    {
        $tok = Jwt::sign(self::$es, self::claims(), ['kid' => self::$rs->kid]);
        self::rejects(E::Algorithm, self::make(), $tok); // rs.jwk declares alg RS256
        $loose = TestKey::make('RS256', 'rs-noalg', false);
        self::$published[] = $loose->jwk;
        self::rejects(E::Signature, self::make(), Jwt::sign(self::$es, self::claims(), ['kid' => $loose->kid]));
        $looseEd = TestKey::make('EdDSA', 'ed-noalg', false);
        self::$published[] = $looseEd->jwk;
        self::rejects(E::Signature, self::make(), Jwt::sign(self::$es, self::claims(), ['kid' => $looseEd->kid]));
        self::rejects(E::Signature, self::make(), Jwt::sign(self::$ps, self::claims(), ['kid' => $looseEd->kid]));
    }

    public function testRejectsAnIdTokenAndUntypedTokensAsAccessTokens(): void
    {
        $v = self::make();
        self::rejects(E::TokenType, $v, Jwt::sign(self::$es, self::claims(), ['typ' => 'JWT']));
        self::rejects(E::TokenType, $v, Jwt::sign(self::$es, self::claims(), ['typ' => null]));
        self::rejects(E::TokenType, $v, Jwt::sign(self::$es, self::claims(), ['typ' => 'logout+jwt']));
        self::rejects(E::TokenType, $v, Jwt::sign(self::$es, self::claims(), ['typ' => 7]));
    }

    public function testRejectsExpiredTokensHonouringTheClockSkew(): void
    {
        $clock = new Clock((self::NOW + 300 + 29) * 1000);
        $v = self::make([], $clock);
        $v->verify(Jwt::sign(self::$es, self::claims())); // within 30 s skew
        $clock->now = (self::NOW + 300 + 31) * 1000;
        self::rejects(E::Expired, $v, Jwt::sign(self::$es, self::claims()));
        self::rejects(E::Expired, self::make(), Jwt::sign(self::$es, self::claims(['exp' => null])));
        self::rejects(E::Expired, self::make(), Jwt::sign(self::$es, self::claims(['exp' => self::NOW - 100])));
        self::make(['clockSkewMs' => 0], new Clock((self::NOW + 300) * 1000))->verify(Jwt::sign(self::$es, self::claims()));
        self::rejects(E::Expired, self::make(['clockSkewMs' => 0], new Clock((self::NOW + 300) * 1000 + 1)), Jwt::sign(self::$es, self::claims()));
    }

    public function testRejectsNotYetValidAndFutureIssuedTokens(): void
    {
        $v = self::make();
        self::rejects(E::NotYetValid, $v, Jwt::sign(self::$es, self::claims(['nbf' => self::NOW + 120])));
        $v->verify(Jwt::sign(self::$es, self::claims(['nbf' => self::NOW + 20])));
        self::rejects(E::FutureIssued, $v, Jwt::sign(self::$es, self::claims(['iat' => self::NOW + 120])));
        $v->verify(Jwt::sign(self::$es, self::claims(['iat' => self::NOW + 30])));
    }

    public function testRejectsNonNumericTimeClaimsAndMalformedClaimTypes(): void
    {
        $v = self::make();
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['exp' => (string) (self::NOW + 300)])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['scope' => ['orders:read']])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['act' => 'admin'])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['act' => ['iss' => self::ISS]])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['aud' => 42])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['aud' => [self::AUD, 7]])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['nbf' => true])));
        self::rejects(E::Malformed, $v, Jwt::sign(self::$es, self::claims(['authz_version' => '43'])));
        $header = Jwt::encode(['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => self::$es->kid]);
        $noIat = self::claims();
        unset($noIat['iat']);
        $body = Jwt::encode($noIat);
        self::rejects(E::Malformed, $v, Jwt::signRaw(self::$es, $header, substr($body, 0, -1) . ',"iat":1e400}'), 'non-finite number');
    }

    public function testRejectsDuplicateJsonMembersInPayloadAndHeader(): void
    {
        $v = self::make();
        $es = self::$es;
        $header = Jwt::encode(['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => $es->kid]);
        $body = Jwt::encode(self::claims());
        self::rejects(E::DuplicateClaim, $v, Jwt::signRaw($es, $header, substr($body, 0, -1) . ',"sub":"usr_admin"}'));
        self::rejects(E::DuplicateClaim, $v, Jwt::signRaw($es, $header, substr($body, 0, -1) . ',"aud":"' . self::AUD . '"}'));
        self::rejects(E::DuplicateClaim, $v, Jwt::signRaw($es, $header, substr($body, 0, -1) . ',"\\u0069ss":"https://evil.test"}'));
        self::rejects(E::DuplicateClaim, $v, Jwt::signRaw($es, $header, substr($body, 0, -1) . ',"act":{"sub":"a","sub":"b"}}'));
        self::rejects(E::DuplicateClaim, $v, Jwt::signRaw($es, '{"alg":"ES256","typ":"at+jwt","kid":"' . $es->kid . '","kid":"' . self::$rs->kid . '"}', $body));
        self::rejects(E::DuplicateClaim, $v, Jwt::signRaw($es, '{"alg":"none","typ":"at+jwt","kid":"' . $es->kid . '","alg":"ES256"}', $body));
        self::assertSame(0, $v->fetchCount());
    }

    public function testRejectsTrailingDataAndMalformedStructure(): void
    {
        $v = self::make();
        $es = self::$es;
        $header = Jwt::encode(['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => $es->kid]);
        $good = Jwt::sign($es, self::claims());
        self::rejects(E::Malformed, $v, $good . '.extra');
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, $header, Jwt::encode(self::claims()) . ' {}'));
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, $header . 'x', Jwt::encode(self::claims())));
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, $header, '[1,2]'));
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, '[]', Jwt::encode(self::claims())));
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, $header, "\u{FEFF}" . Jwt::encode(self::claims())));
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, $header, substr(Jwt::encode(self::claims()), 0, -1) . ',"x":"' . "\xff" . '"}'));
        self::rejects(E::Malformed, $v, 'a.b');
        self::rejects(E::Malformed, $v, 'a.b.c');
        [$h, $p, $s] = explode('.', $good);
        self::rejects(E::Malformed, $v, "{$h}=.{$p}.{$s}");
        self::rejects(E::Malformed, $v, $h . '.' . $p . '.' . str_replace('-', '+', $s) . '+');
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, Jwt::encode(['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => $es->kid, 'crit' => ['exp']]), Jwt::encode(self::claims())));
        self::rejects(E::MissingToken, $v, '');
        $deep = '{"iss":"' . self::ISS . '","x":' . str_repeat('[', 40) . str_repeat(']', 40) . '}';
        self::rejects(E::Malformed, $v, Jwt::signRaw($es, $header, $deep));
        self::assertSame(0, $v->fetchCount());
    }

    public function testRejectsAnOversizedTokenBeforeParsingOrFetching(): void
    {
        $v = self::make();
        $tok = Jwt::sign(self::$es, self::claims(['pad' => str_repeat('x', 9000)]));
        self::assertTrue(strlen($tok) > 8192);
        self::rejects(E::TooLarge, $v, $tok);
        self::rejects(E::TooLarge, self::make(['maxTokenBytes' => 100]), Jwt::sign(self::$es, self::claims()));
        self::assertSame(0, $v->fetchCount());
    }

    public function testRejectsATamperedPayloadOrSignature(): void
    {
        $v = self::make();
        foreach ([self::$es, self::$rs, self::$ps, self::$ed] as $k) {
            [$h, , $s] = explode('.', Jwt::sign($k, self::claims()));
            $forged = Jwt::b64(Jwt::encode(self::claims(['sub' => 'usr_admin'])));
            self::rejects(E::Signature, $v, "{$h}.{$forged}.{$s}", $k->alg);
            $other = Jwt::sign(TestKey::make($k->alg, $k->kid), self::claims());
            self::rejects(E::Signature, $v, $other, $k->alg . ' other key, same kid');
        }
    }

    public function testRejectsImpersonationAndUnknownTokenKindsOffline(): void
    {
        $v = self::make();
        self::rejects(E::TokenKind, $v, Jwt::sign(self::$es, self::claims(['token_kind' => 'impersonation_access', 'act' => ['sub' => 'usr_agent'], 'impersonation_grant_id' => 'imp_1'])));
        self::rejects(E::TokenKind, $v, Jwt::sign(self::$es, self::claims(['token_kind' => null])));
        self::rejects(E::TokenKind, $v, Jwt::sign(self::$es, self::claims(['token_kind' => 'refresh'])));
        self::rejects(E::TokenKind, $v, Jwt::sign(self::$es, self::claims(['sub' => ''])));
        self::rejects(E::TokenKind, $v, Jwt::sign(self::$es, self::claims(['client_id' => null])));
        self::rejects(E::TokenKind, $v, Jwt::sign(self::$es, self::claims(['jti' => null])));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['acceptedKinds' => ['user_access', 'impersonation_access']]), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'SupportGuard'));
        self::rejects(E::TokenKind, self::make(['acceptedKinds' => ['service_access']]), Jwt::sign(self::$es, self::claims()));
    }

    public function testBoundsJwksFetchesUnderAnUnknownKidFlood(): void
    {
        $clock = new Clock(self::NOW * 1000);
        $v = self::make([], $clock);
        // A flood of random key IDs: one fetch, all rejected, never fail-open.
        for ($i = 0; $i < 200; $i++) {
            self::rejects(E::UnknownKey, $v, Jwt::sign(self::$es, self::claims(), ['kid' => bin2hex(random_bytes(8))]));
        }
        self::assertSame(1, $v->fetchCount());
        // Known keys keep working during the flood.
        $v->verify(Jwt::sign(self::$es, self::claims()));
        // After the interval, one more refresh is allowed, then the bound applies again.
        $clock->now += 61_000;
        for ($i = 0; $i < 50; $i++) {
            self::rejects(E::UnknownKey, $v, Jwt::sign(self::$es, self::claims(['exp' => self::NOW + 400]), ['kid' => 'later-' . $i]));
        }
        self::assertSame(2, $v->fetchCount());
    }

    public function testPicksUpARotatedKeyAfterTheRefreshInterval(): void
    {
        $clock = new Clock(self::NOW * 1000);
        $v = self::make([], $clock);
        $v->verify(Jwt::sign(self::$es, self::claims()));
        $next = TestKey::make('ES256', 'es-2');
        self::$published[] = $next->jwk;
        self::rejects(E::UnknownKey, $v, Jwt::sign($next, self::claims())); // within the interval
        $clock->now += 60_000;
        $c = $v->verify(Jwt::sign($next, self::claims(['exp' => self::NOW + 400])));
        self::assertSame('usr_1', $c->subject);
        $v->verify(Jwt::sign(self::$es, self::claims(['exp' => self::NOW + 400]))); // planned overlap
        self::assertSame(2, $v->fetchCount());
        // A retired key disappears with the next successful refresh.
        self::$published = [$next->jwk];
        $clock->now += 60_000;
        self::rejects(E::UnknownKey, $v, Jwt::sign(TestKey::make('ES256', 'es-3'), self::claims(['exp' => self::NOW + 500])));
        self::rejects(E::UnknownKey, $v, Jwt::sign(self::$es, self::claims(['exp' => self::NOW + 500])));
    }

    public function testFailsClosedWhenTheKeySetIsUnavailable(): void
    {
        $v = self::make();
        self::$status = 500;
        self::rejects(E::Unavailable, $v, Jwt::sign(self::$es, self::claims()));
        self::rejects(E::Unavailable, $v, Jwt::sign(self::$es, self::claims())); // no fetch storm, still closed
        self::assertSame(1, $v->fetchCount());
        self::$status = 200;
        $dead = new Verifier(issuer: self::ISS, audience: self::AUD, jwksUrl: 'http://127.0.0.1:1/jwks', now: static fn (): int => self::NOW * 1000);
        $e = self::assertVerifierError(E::Unavailable, static fn () => $dead->verify(Jwt::sign(self::$es, self::claims())));
        self::assertInstanceOf(\Throwable::class, $e->getPrevious(), 'the cause is kept');
        foreach (['{"keys":{}}', '{"nokeys":[]}', '[]', 'not json', '{"keys":[],"keys":[]}'] as $bad) {
            $t = new FakeTransport(static fn (): Response => FakeTransport::json(200, $bad));
            $v2 = self::make(['transport' => $t]);
            self::rejects(E::Unavailable, $v2, Jwt::sign(self::$es, self::claims()), $bad);
        }
        $t = new FakeTransport(static fn (): Response => new Response(307, ['location' => 'https://elsewhere.test/jwks']));
        self::rejects(E::Unavailable, self::make(['transport' => $t]), Jwt::sign(self::$es, self::claims()), 'redirects are not followed');
        $t = new FakeTransport(static fn (): Response => FakeTransport::json(200, ['keys' => self::$published, 'pad' => str_repeat('x', 1 << 20)]));
        self::rejects(E::Unavailable, self::make(['transport' => $t]), Jwt::sign(self::$es, self::claims()), 'oversized key set');
    }

    public function testKeepsKnownKeysWhenARefreshFails(): void
    {
        $clock = new Clock(self::NOW * 1000);
        $v = self::make([], $clock);
        $v->verify(Jwt::sign(self::$es, self::claims()));
        self::$status = 503;
        $clock->now += 61_000;
        self::rejects(E::Unavailable, $v, Jwt::sign(self::$es, self::claims(['exp' => self::NOW + 400]), ['kid' => 'unknown']));
        $v->verify(Jwt::sign(self::$es, self::claims(['exp' => self::NOW + 400])));
    }

    public function testSkipsUnusableJwksEntriesAndAmbiguousKeyIds(): void
    {
        $enc = TestKey::make('ES256', 'enc-1');
        $priv = TestKey::make('ES256', 'priv-1');
        $dupA = TestKey::make('ES256', 'dup');
        $dupB = TestKey::make('ES256', 'dup');
        $ops = TestKey::make('ES256', 'ops-1');
        $offCurve = TestKey::make('ES256', 'off-1');
        $bad = $offCurve->jwk;
        $y = (string) base64_decode(strtr($bad['y'], '-_', '+/'));
        $y[31] = chr(ord($y[31]) ^ 1);
        $bad['y'] = Jwt::b64($y);
        $padded = TestKey::make('ES256', 'pad-1');
        $paddedJwk = $padded->jwk;
        $paddedJwk['x'] .= '=';
        $t = new FakeTransport(static fn (): Response => FakeTransport::json(200, ['keys' => [
            ['use' => 'enc'] + $enc->jwk,
            $priv->privateJwk(),
            ['kty' => 'oct', 'kid' => 'hmac', 'k' => Jwt::b64('secret')],
            $dupA->jwk,
            $dupB->jwk,
            ['kty' => 'RSA', 'kid' => 'weak', 'n' => Jwt::b64("\xc1" . random_bytes(127)), 'e' => 'AQAB'],
            ['key_ops' => ['sign']] + $ops->jwk,
            $bad,
            $paddedJwk,
            ['kty' => 'EC', 'crv' => 'P-384', 'kid' => 'p384', 'x' => Jwt::b64(random_bytes(48)), 'y' => Jwt::b64(random_bytes(48))],
            'garbage',
            self::$es->jwk,
        ]]));
        $v = self::make(['transport' => $t]);
        $v->verify(Jwt::sign(self::$es, self::claims()));
        foreach ([$enc, $priv, $dupA, $ops, $offCurve, $padded] as $k) {
            self::rejects(E::UnknownKey, $v, Jwt::sign($k, self::claims()), $k->kid);
        }
        $input = Jwt::b64(Jwt::encode(['alg' => 'HS256', 'typ' => 'at+jwt', 'kid' => 'hmac'])) . '.' . Jwt::b64(Jwt::encode(self::claims()));
        self::rejects(E::Algorithm, $v, $input . '.' . Jwt::b64(hash_hmac('sha256', $input, 'secret', true)));
    }

    public function testRejectsRsaKeysShorterThan2048Bits(): void
    {
        $weak = TestKey::make('RS256', 'rs-1024', true, 1024);
        $odd = TestKey::make('RS256', 'rs-2047', true, 2047);
        self::$published = [$weak->jwk, $odd->jwk, self::$es->jwk];
        $v = self::make();
        self::rejects(E::UnknownKey, $v, Jwt::sign($weak, self::claims()));
        self::rejects(E::UnknownKey, $v, Jwt::sign($odd, self::claims()));
    }

    public function testValidatesConfiguration(): void
    {
        $msg = static fn (string $part): \Closure => static fn (\Throwable $e): bool => str_contains($e->getMessage(), $part);
        self::assertThrows(\InvalidArgumentException::class, static fn () => new Verifier(issuer: '', audience: self::AUD), $msg('issuer and audience'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => new Verifier(issuer: self::ISS, audience: ''), $msg('issuer and audience'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['clockSkewMs' => 61_000]), $msg('at most 60s'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['clockSkewMs' => -1]), $msg('non-negative'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['minRefreshIntervalMs' => 0]), $msg('at least 1000'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['jwksUrl' => 'file:///etc/passwd']), $msg('http'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['jwksUrl' => 'https://user:pw@id.test/jwks']), $msg('credentials'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['jwksUrl' => 'not a url']), $msg('absolute URL'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['maxTokenBytes' => 0]), $msg('maxTokenBytes'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::make(['timeoutMs' => 0]), $msg('timeoutMs'));
        $d = new Verifier(issuer: self::ISS . '/', audience: self::AUD);
        self::assertSame(self::ISS . '/', $d->issuer);
        self::assertSame(self::AUD, $d->audience);
    }

    public function testDerivesTheDefaultJwksUrlFromTheIssuer(): void
    {
        $t = self::jwksServer();
        $v = new Verifier(issuer: self::ISS . '/', audience: self::AUD, transport: $t, now: static fn (): int => self::NOW * 1000);
        self::rejects(E::Issuer, $v, Jwt::sign(self::$es, self::claims()));
        $v = new Verifier(issuer: self::ISS, audience: self::AUD, transport: $t, now: static fn (): int => self::NOW * 1000);
        $v->verify(Jwt::sign(self::$es, self::claims()));
        self::assertSame(self::ISS . '/jwks', $t->last()->url);
        self::assertSame('application/jwk-set+json, application/json', $t->last()->header('accept'));
        self::assertSame(5000, $t->last()->timeoutMs);
        self::assertSame(1 << 20, $t->last()->maxResponseBytes);
    }

    public function testClaimsHelpersEnforceScopeAndOrganization(): void
    {
        $c = self::make()->verify(Jwt::sign(self::$es, self::claims()));
        self::assertTrue($c->hasScope('orders:read'));
        self::assertFalse($c->hasScope('orders:delete'));
        $c->requireScope('orders:read', 'orders:create');
        $e = self::assertVerifierError(E::Scope, static fn () => $c->requireScope('orders:read', 'orders:refund'));
        self::assertSame(['orders:read', 'orders:refund'], $e->scopes);
        $c->requireOrganization('org_a');
        self::assertVerifierError(E::Organization, static fn () => $c->requireOrganization('org_b'));
        self::assertVerifierError(E::Organization, static fn () => $c->requireOrganization(''));
        $noOrg = self::make()->verify(Jwt::sign(self::$es, self::claims(['org_id' => null])));
        self::assertVerifierError(E::Organization, static fn () => $noOrg->requireOrganization(''));
        self::assertFalse($c->isSupport());
        $spaced = self::make()->verify(Jwt::sign(self::$es, self::claims(['scope' => " a\u{00A0}b\tc\u{3000}d  "])));
        self::assertSame(['a', 'b', 'c', 'd'], $spaced->scopes, 'scope is split on JavaScript whitespace');
    }

    public function testNeverPutsTokenMaterialInErrorMessages(): void
    {
        $tok = Jwt::sign(self::$es, self::claims(['aud' => 'https://api.test/other']));
        $e = self::assertVerifierError(E::Audience, static fn () => self::make()->verify($tok));
        self::assertStringNotContains(explode('.', $tok)[1], $e->getMessage());
        self::assertStringNotContains('usr_1', $e->getMessage());
        self::assertSame('verifier: wrong audience', $e->getMessage());
        self::assertTrue(VerifierException::matches($e, E::Audience));
        self::assertFalse(VerifierException::matches($e, E::Issuer));
        self::assertTrue($e->is(E::Issuer, E::Audience));
        self::assertSame(24, count(E::cases()), 'the same 24 categories as the Node SDK');
    }

    public function testSharesTheKeySetAcrossInstancesThroughAStore(): void
    {
        // Under PHP-FPM every request builds its own Verifier; the store makes the
        // cache and its refresh bound application-wide.
        $store = new MemoryStore();
        $clock = new Clock(self::NOW * 1000);
        $t = self::jwksServer();
        $request = static fn (): Verifier => self::make(['cache' => $store, 'transport' => $t], $clock);
        $request()->verify(Jwt::sign(self::$es, self::claims()));
        $request()->verify(Jwt::sign(self::$rs, self::claims()));
        self::assertSame(1, $t->hits(), 'later requests reuse the stored key set');
        for ($i = 0; $i < 20; $i++) {
            self::rejects(E::UnknownKey, $request(), Jwt::sign(self::$es, self::claims(), ['kid' => 'flood-' . $i]));
        }
        self::assertSame(1, $t->hits(), 'an unknown-kid flood across requests stays bounded');
        $clock->now += 61_000;
        $next = TestKey::make('ES256', 'es-next');
        self::$published[] = $next->jwk;
        $request()->verify(Jwt::sign($next, self::claims(['exp' => self::NOW + 400])));
        self::assertSame(2, $t->hits());
        $request()->verify(Jwt::sign($next, self::claims(['exp' => self::NOW + 400])));
        self::assertSame(2, $t->hits());
    }

    public function testSharesFailureStateAcrossInstancesThroughAStore(): void
    {
        $store = new MemoryStore();
        $t = self::jwksServer();
        self::$status = 500;
        for ($i = 0; $i < 5; $i++) {
            self::rejects(E::Unavailable, self::make(['cache' => $store, 'transport' => $t]), Jwt::sign(self::$es, self::claims()));
        }
        self::assertSame(1, $t->hits(), 'no fetch storm while the key set is down');
    }

    public function testFileStoreSharesTheKeySet(): void
    {
        $dir = sys_get_temp_dir() . '/proudauth-php-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        try {
            $t = self::jwksServer();
            self::make(['cache' => new FileStore($dir), 'transport' => $t])->verify(Jwt::sign(self::$ed, self::claims()));
            self::make(['cache' => new FileStore($dir), 'transport' => $t])->verify(Jwt::sign(self::$ps, self::claims()));
            self::assertSame(1, $t->hits());
            $files = glob($dir . '/proudauth-*.cache') ?: [];
            self::assertCount(1, $files);
            self::assertSame('0600', substr(sprintf('%o', fileperms($files[0])), -4));
            // A corrupted cache file is ignored, not trusted.
            file_put_contents($files[0], '{"url":"' . self::JWKS . '","document":"{\"keys\":[1]}","lastFetch":0,"lastFailed":false}');
            self::make(['cache' => new FileStore($dir), 'transport' => $t])->verify(Jwt::sign(self::$es, self::claims()));
            self::assertSame(2, $t->hits());
            self::assertThrows(\InvalidArgumentException::class, static fn () => new FileStore($dir . '/missing'));
        } finally {
            array_map('unlink', glob($dir . '/*') ?: []);
            rmdir($dir);
        }
    }
}

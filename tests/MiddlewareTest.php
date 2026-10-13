<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Middleware\BearerToken;
use ProudAuth\Sdk\Middleware\Challenge;
use ProudAuth\Sdk\Middleware\RequestAuthenticator;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Tests\Support\Jwt;
use ProudAuth\Sdk\Tests\Support\TestKey;
use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\Verifier;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Port of sdk/node/test/middleware.test.ts for the framework-neutral helpers.
 */
final class MiddlewareTest extends TestCase
{
    private const ISS = 'https://id.test/realms/main';
    private const AUD = 'https://api.test/orders';

    private static TestKey $key;

    public static function setUpBeforeClass(): void
    {
        self::$key = TestKey::make('ES256', 'k1');
    }

    private static function token(array $extra = []): string
    {
        $now = time();
        return Jwt::sign(self::$key, array_merge([
            'iss' => self::ISS, 'sub' => 'usr_1', 'aud' => self::AUD, 'client_id' => 'web', 'iat' => $now, 'exp' => $now + 300,
            'jti' => 'j1', 'scope' => 'orders:read', 'org_id' => 'org_a', 'token_kind' => 'user_access',
        ], $extra));
    }

    private static function verifier(bool $up = true): Verifier
    {
        return new Verifier(
            issuer: self::ISS,
            audience: self::AUD,
            jwksUrl: 'https://id.test/jwks',
            minRefreshIntervalMs: 1_000,
            transport: new FakeTransport(static fn (): Response => $up ? FakeTransport::json(200, ['keys' => [self::$key->jwk]]) : FakeTransport::json(500, [])),
        );
    }

    public function testExtractsABearerTokenFromTheAuthorizationHeaderOnly(): void
    {
        self::assertSame('abc.def.ghi', BearerToken::fromHeader('Bearer abc.def.ghi'));
        self::assertSame('pa_it_x-y_z', BearerToken::fromHeader('bearer   pa_it_x-y_z  '));
        self::assertSame('t', BearerToken::fromHeader('BEARER t', '/orders?x=1'));
        self::assertSame('a/b+c=', BearerToken::fromHeader(['Bearer a/b+c=']));
    }

    public function testRefusesAccessTokensInTheQueryStringEvenWithAHeader(): void
    {
        foreach (['/orders?access_token=abc', '/orders?a=1&access_token=abc', '/orders?access%5Ftoken=abc', '/orders?access_token', '/x?a=1&access_token=#frag'] as $uri) {
            self::assertVerifierError(E::InvalidRequest, static fn () => BearerToken::fromHeader('Bearer abc', $uri), $uri);
        }
        self::assertSame('abc', BearerToken::fromHeader('Bearer abc', '/orders?access.token=abc'), 'no PHP name mangling');
        self::assertSame('abc', BearerToken::fromHeader('Bearer abc', '/orders?x=1#access_token=abc'), 'the fragment is not query');
        self::assertVerifierError(E::InvalidRequest, static fn () => BearerToken::fromGlobals(['REQUEST_URI' => '/api/x?access_token=abc']));
        self::assertVerifierError(E::InvalidRequest, static fn () => BearerToken::fromGlobals(['QUERY_STRING' => 'access_token=abc', 'HTTP_AUTHORIZATION' => 'Bearer x']));
    }

    public function testReportsMissingAndMalformedCredentials(): void
    {
        $missing = static fn (\Closure $fn) => self::assertVerifierError(E::MissingToken, $fn);
        $missing(static fn () => BearerToken::fromHeader(null));
        $missing(static fn () => BearerToken::fromHeader('Basic dXNlcjpwYXNz'));
        $missing(static fn () => BearerToken::fromHeader('Bearer '));
        $missing(static fn () => BearerToken::fromHeader('Bearer    '));
        $missing(static fn () => BearerToken::fromHeader('Bearertoken'));
        $missing(static fn () => BearerToken::fromGlobals([]));
        self::assertVerifierError(E::Malformed, static fn () => BearerToken::fromHeader('Bearer a b'));
        self::assertVerifierError(E::Malformed, static fn () => BearerToken::fromHeader('Bearer a,b'));
        self::assertVerifierError(E::Malformed, static fn () => BearerToken::fromHeader('Bearer a=b'));
        self::assertVerifierError(E::Malformed, static fn () => BearerToken::fromHeader(["Bearer a\nb"]));
        self::assertVerifierError(E::InvalidRequest, static fn () => BearerToken::fromHeader(['Bearer a', 'Bearer b']));
        self::assertVerifierError(E::MissingToken, static fn () => BearerToken::fromHeader([]), 'PSR-7 getHeader() of an absent header');
    }

    public function testReadsTheHeaderFromPhpSuperglobals(): void
    {
        self::assertSame('abc', BearerToken::fromGlobals(['HTTP_AUTHORIZATION' => 'Bearer abc', 'REQUEST_URI' => '/x']));
        self::assertSame('abc', BearerToken::fromGlobals(['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer abc']));
        $saved = $_SERVER;
        try {
            $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer from-server';
            $_SERVER['REQUEST_URI'] = '/';
            self::assertSame('from-server', BearerToken::fromGlobals());
        } finally {
            $_SERVER = $saved;
        }
    }

    public function testMapsErrorCategoriesToRfc6750Responses(): void
    {
        $c = Challenge::fromThrowable(new VerifierException(E::MissingToken));
        self::assertSame(401, $c->status);
        self::assertSame(['www-authenticate' => 'Bearer'], $c->headers);
        self::assertNull($c->error);
        self::assertSame(['www-authenticate' => 'Bearer realm="orders \\"api\\""'], Challenge::fromThrowable(new VerifierException(E::MissingToken), 'orders "api"')->headers);
        self::assertSame(['www-authenticate' => 'Bearer realm="a\\\\b c"'], Challenge::fromThrowable(new VerifierException(E::MissingToken), "a\\b\nc")->headers);
        self::assertSame('Bearer error="invalid_token"', Challenge::fromThrowable(new VerifierException(E::Expired))->headers['www-authenticate']);
        self::assertSame('invalid_token', Challenge::fromThrowable(new VerifierException(E::Expired))->error);
        self::assertSame(400, Challenge::fromThrowable(new VerifierException(E::InvalidRequest))->status);
        self::assertSame('Bearer error="invalid_request"', Challenge::fromThrowable(new VerifierException(E::InvalidRequest))->headers['www-authenticate']);
        $scope = Challenge::fromThrowable(new VerifierException(E::Scope), null, ['orders:write']);
        self::assertSame(403, $scope->status);
        self::assertSame('Bearer error="insufficient_scope", scope="orders:write"', $scope->headers['www-authenticate']);
        self::assertSame('insufficient_scope', $scope->error);
        self::assertSame('Bearer error="insufficient_scope"', Challenge::fromThrowable(new VerifierException(E::Scope))->headers['www-authenticate']);
        $org = Challenge::fromThrowable(new VerifierException(E::Organization));
        self::assertSame([403, ['www-authenticate' => 'Bearer error="insufficient_scope"'], 'insufficient_scope'], [$org->status, $org->headers, $org->error]);
        $sp = Challenge::fromThrowable(new VerifierException(E::SupportPolicy));
        self::assertSame([403, []], [$sp->status, $sp->headers]);
        self::assertSame([503, []], [Challenge::fromThrowable(new VerifierException(E::Unavailable))->status, Challenge::fromThrowable(new VerifierException(E::Unavailable))->headers]);
        self::assertSame(503, Challenge::fromThrowable(new VerifierException(E::StaleState))->status);
        self::assertSame(500, Challenge::fromThrowable(new VerifierException(E::Contract))->status);
        self::assertSame(500, Challenge::fromThrowable(new \RuntimeException('boom'))->status);
        foreach ([E::Malformed, E::TooLarge, E::DuplicateClaim, E::TokenType, E::Algorithm, E::UnknownKey, E::Signature, E::Issuer, E::Audience, E::NotYetValid, E::FutureIssued, E::TokenKind, E::Inactive, E::Revoked] as $code) {
            self::assertSame(401, Challenge::fromThrowable(new VerifierException($code))->status, $code->value);
        }
        $all = Challenge::fromThrowable(new VerifierException(E::Expired))->responseHeaders();
        self::assertSame('no-store', $all['cache-control']);
        self::assertSame('text/plain; charset=utf-8', $all['content-type']);
        self::assertSame('Unauthorized', Challenge::fromThrowable(new VerifierException(E::Expired))->body());
        self::assertSame('Service Unavailable', Challenge::fromThrowable(new VerifierException(E::Unavailable))->body());
    }

    /**
     * @return array{status: int, headers: array<string, string>, body: string, result: mixed}
     */
    private static function serve(RequestAuthenticator|Authenticator $auth, \Closure $handler, array $server, ?\Closure $onError = null, ?\Closure $onHandlerError = null): array
    {
        $out = ['status' => 200, 'headers' => [], 'body' => '', 'result' => null];
        $emit = static function (int $status, array $headers, string $body) use (&$out): void {
            $out['status'] = $status;
            $out['headers'] = $headers;
            $out['body'] = $body;
        };
        $ra = $auth instanceof RequestAuthenticator ? $auth : new RequestAuthenticator($auth, onError: $onError, onHandlerError: $onHandlerError, emit: $emit);
        $out['result'] = $ra->protect($handler, $server);
        return $out;
    }

    public function testPassesVerifiedClaimsToTheHandler(): void
    {
        $seen = null;
        $res = self::serve(self::verifier(), static function (Claims $c) use (&$seen): string {
            $seen = $c;
            return 'ok:' . $c->subject;
        }, ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token(), 'REQUEST_URI' => '/orders']);
        self::assertSame(200, $res['status']);
        self::assertSame('ok:usr_1', $res['result']);
        self::assertSame('usr_1', $seen?->subject);
    }

    public function testChallengesAMissingTokenWithoutAnErrorCode(): void
    {
        $res = self::serve(self::verifier(), static fn (): string => 'ran', ['REQUEST_URI' => '/orders']);
        self::assertSame(401, $res['status']);
        self::assertSame('Bearer', $res['headers']['www-authenticate']);
        self::assertSame('no-store', $res['headers']['cache-control']);
        self::assertNull($res['result']);
    }

    public function testRejectsInvalidTokensWithInvalidTokenAndNeverRunsTheHandler(): void
    {
        $errors = [];
        $ran = false;
        $idToken = Jwt::sign(self::$key, ['iss' => self::ISS, 'sub' => 'usr_1', 'aud' => self::AUD, 'exp' => time() + 60], ['typ' => 'JWT']);
        foreach ([self::token(['aud' => 'https://api.test/billing']), $idToken, 'not-a-jwt'] as $t) {
            $res = self::serve(self::verifier(), static function () use (&$ran): void {
                $ran = true;
            }, ['HTTP_AUTHORIZATION' => 'Bearer ' . $t], static function (\Throwable $e) use (&$errors): void {
                $errors[] = $e instanceof VerifierException ? $e->errorCode->value : 'other';
            });
            self::assertSame(401, $res['status']);
            self::assertSame('Bearer error="invalid_token"', $res['headers']['www-authenticate']);
            self::assertStringNotContains($t, $res['body']);
        }
        self::assertFalse($ran);
        self::assertSame(['audience', 'token_type', 'malformed'], $errors);
    }

    public function testAnswers400InvalidRequestForAQueryStringToken(): void
    {
        $res = self::serve(self::verifier(), static fn (): string => 'ran', ['REQUEST_URI' => '/orders?access_token=' . self::token()]);
        self::assertSame(400, $res['status']);
        self::assertSame('Bearer error="invalid_request"', $res['headers']['www-authenticate']);
    }

    public function testEnforcesScopesWith403InsufficientScope(): void
    {
        $handler = static function (Claims $c): string {
            RequestAuthenticator::requireScopes($c, 'orders:write');
            return 'wrote';
        };
        $denied = self::serve(self::verifier(), $handler, ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token()]);
        self::assertSame(403, $denied['status']);
        self::assertSame('Bearer error="insufficient_scope", scope="orders:write"', $denied['headers']['www-authenticate']);
        $ok = self::serve(self::verifier(), $handler, ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token(['scope' => 'orders:read orders:write'])]);
        self::assertSame(200, $ok['status']);
        self::assertSame('wrote', $ok['result']);
        $org = self::serve(self::verifier(), static fn (Claims $c) => $c->requireOrganization('org_b'), ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token()]);
        self::assertSame(403, $org['status']);
        $ra = new RequestAuthenticator(self::verifier(), realm: 'orders');
        $claims = $ra->authenticate('Bearer ' . self::token(), '/orders');
        self::assertSame('Bearer realm="orders", error="insufficient_scope", scope="a b"', $ra->challenge(new VerifierException(E::Scope), ['a', 'b'])->headers['www-authenticate']);
        self::assertSame('usr_1', $claims->subject);
    }

    public function testAnswers500WhenTheHandlerFailsAndReportsIt(): void
    {
        $reported = [];
        $res = self::serve(self::verifier(), static function (): never {
            throw new \RuntimeException('handler bug');
        }, ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token()], null, static function (\Throwable $e) use (&$reported): void {
            $reported[] = $e->getMessage();
        });
        self::assertSame(500, $res['status']);
        self::assertSame('Internal Server Error', $res['body']);
        self::assertSame(['handler bug'], $reported);
    }

    public function testAnswers503FailClosedWhenKeysCannotBeLoaded(): void
    {
        $res = self::serve(self::verifier(false), static fn (): string => 'should not run', ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token()]);
        self::assertSame(503, $res['status']);
        self::assertTrue(!isset($res['headers']['www-authenticate']));
        self::assertNull($res['result']);
    }

    public function testTelemetryFailuresDoNotChangeTheOutcome(): void
    {
        $res = self::serve(self::verifier(), static fn (): string => 'ran', [], static function (): void {
            throw new \RuntimeException('metrics down');
        });
        self::assertSame(401, $res['status']);
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Admin\AdminClient;
use ProudAuth\Sdk\Admin\ProblemException;
use ProudAuth\Sdk\Admin\Secret;
use ProudAuth\Sdk\Http\CurlTransport;
use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\TransportException;
use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Introspection\Introspector;
use ProudAuth\Sdk\Tests\Support\Jwt;
use ProudAuth\Sdk\Tests\Support\PhpServer;
use ProudAuth\Sdk\Tests\Support\TestKey;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;

/**
 * Real sockets: CurlTransport against PHP's built-in web server (started on
 * 127.0.0.1 by this test), and the SDK's request helpers answering real HTTP
 * requests (status lines, WWW-Authenticate and Cache-Control headers).
 */
final class HttpIntegrationTest extends TestCase
{
    private static PhpServer $server;
    private static TestKey $key;
    private static string $jwksFile;

    public static function setUpBeforeClass(): void
    {
        self::$key = TestKey::make('ES256', 'int-1');
        self::$jwksFile = (string) tempnam(sys_get_temp_dir(), 'proudauth-jwks-');
        file_put_contents(self::$jwksFile, json_encode(['keys' => [self::$key->jwk]], JSON_UNESCAPED_SLASHES));
        self::$server = PhpServer::start(__DIR__ . '/server/router.php', ['PROUDAUTH_TEST_JWKS' => self::$jwksFile]);
    }

    public static function tearDownAfterClass(): void
    {
        self::$server->stop();
        @unlink(self::$jwksFile);
    }

    private static function send(string $method, string $path, array $headers = [], ?string $body = null, int $timeoutMs = 5000, int $max = 1 << 20): \ProudAuth\Sdk\Http\Response
    {
        return (new CurlTransport())->send(new Request($method, self::$server->url . $path, $headers, $body, $timeoutMs, $max));
    }

    private static function token(array $extra = []): string
    {
        $now = time();
        return Jwt::sign(self::$key, array_merge([
            'iss' => 'https://id.test/realms/main', 'sub' => 'usr_1', 'aud' => 'https://api.test/orders', 'client_id' => 'web',
            'iat' => $now, 'exp' => $now + 300, 'jti' => 'j1', 'scope' => 'orders:read', 'token_kind' => 'user_access',
        ], $extra));
    }

    public function testCurlTransportSendsTheRequestAndReadsTheResponse(): void
    {
        $res = self::send('POST', '/echo?a=1', ['content-type' => 'application/x-www-form-urlencoded', 'x-custom' => 'v1'], 'token=abc');
        self::assertSame(200, $res->status);
        $echo = json_decode($res->body, true);
        self::assertSame('POST', $echo['method']);
        self::assertSame('/echo?a=1', $echo['uri']);
        self::assertSame('token=abc', $echo['body']);
        self::assertSame('v1', $echo['headers']['x-custom']);
        self::assertTrue(!isset($echo['headers']['expect']), 'no Expect: 100-continue');
        self::assertSame(['a', 'b'], $res->headers['x-multi']);
        self::assertSame('a, b', $res->header('X-Multi'));
        self::assertSame('"e1"', $res->header('etag'));
        self::assertSame(['application/json'], $res->headers['content-type']);
        $big = self::send('PUT', '/echo', [], str_repeat('z', 200_000));
        self::assertSame(200_000, strlen(json_decode($big->body, true)['body']));
        self::assertSame(503, self::send('GET', '/status/503')->status);
        self::assertSame('GET', json_decode(self::send('GET', '/echo')->body, true)['method']);
    }

    public function testCurlTransportDoesNotFollowRedirects(): void
    {
        $res = self::send('GET', '/redirect');
        self::assertSame(307, $res->status);
        $e = self::assertThrows(TransportException::class, static fn () => (new HttpClient())->send('GET', self::$server->url . '/redirect', [], null, 5000, 1000));
        self::assertSame(TransportException::REDIRECT, $e->kind);
        self::assertSame(307, $e->status);
    }

    public function testCurlTransportEnforcesTheDeadline(): void
    {
        $t0 = microtime(true);
        $e = self::assertThrows(TransportException::class, static fn () => self::send('GET', '/slow', [], null, 300));
        self::assertSame(TransportException::TIMEOUT, $e->kind);
        self::assertTrue(microtime(true) - $t0 < 1.2, 'the deadline is honoured');
    }

    public function testCurlTransportStopsReadingOversizedBodies(): void
    {
        $e = self::assertThrows(TransportException::class, static fn () => self::send('GET', '/big-declared', [], null, 5000, 1000));
        self::assertSame(TransportException::TOO_LARGE, $e->kind);
        self::assertSame(200, $e->status);
        $e = self::assertThrows(TransportException::class, static fn () => self::send('GET', '/big-streamed', [], null, 5000, 100_000));
        self::assertSame(TransportException::TOO_LARGE, $e->kind);
        self::assertSame(4 << 20, strlen(self::send('GET', '/big-streamed', [], null, 5000, 4 << 20)->body), 'exactly the limit is fine');
    }

    public function testCurlTransportRefusesOtherProtocolsAndInjectedHeaders(): void
    {
        foreach (['file:///etc/passwd', 'ftp://127.0.0.1/', 'gopher://127.0.0.1/', 'dict://127.0.0.1/'] as $url) {
            $e = self::assertThrows(TransportException::class, static fn () => (new CurlTransport())->send(new Request('GET', $url)), null, $url);
            self::assertSame(TransportException::NETWORK, $e->kind);
        }
        self::assertThrows(TransportException::class, static fn () => self::send('GET', '/echo', ['x-evil' => "a\r\nx-injected: 1"]));
        self::assertThrows(TransportException::class, static fn () => self::send('GET', '/echo', ['x bad' => 'v']));
        self::assertThrows(TransportException::class, static fn () => self::send("GET /x HTTP/1.1\r\nHost: a\r\n\r\nGET", '/echo'));
        self::assertThrows(TransportException::class, static fn () => self::send('', '/echo'));
        $e = self::assertThrows(TransportException::class, static fn () => (new CurlTransport())->send(new Request('GET', 'http://127.0.0.1:1/', [], null, 2000)));
        self::assertSame(TransportException::NETWORK, $e->kind);
        $t = new CurlTransport([CURLOPT_FOLLOWLOCATION => true]);
        self::assertSame(307, $t->send(new Request('GET', self::$server->url . '/redirect'))->status, 'options cannot re-enable redirects');
    }

    public function testProtectAnswersRealRequestsWithRfc6750Responses(): void
    {
        $ok = self::send('GET', '/protected', ['authorization' => 'Bearer ' . self::token()]);
        self::assertSame(200, $ok->status);
        self::assertSame(['subject' => 'usr_1'], json_decode($ok->body, true));

        $missing = self::send('GET', '/protected');
        self::assertSame(401, $missing->status);
        self::assertSame('Bearer realm="orders"', $missing->header('www-authenticate'));
        self::assertSame('no-store', $missing->header('cache-control'));
        self::assertStringContains('text/plain', (string) $missing->header('content-type'));
        self::assertSame('Unauthorized', $missing->body);

        $expired = self::send('GET', '/protected', ['authorization' => 'Bearer ' . self::token(['exp' => time() - 120])]);
        self::assertSame(401, $expired->status);
        self::assertSame('Bearer realm="orders", error="invalid_token"', $expired->header('www-authenticate'));

        $query = self::send('GET', '/protected?access_token=' . self::token());
        self::assertSame(400, $query->status);
        self::assertSame('Bearer realm="orders", error="invalid_request"', $query->header('www-authenticate'));

        $scope = self::send('GET', '/protected/write', ['authorization' => 'Bearer ' . self::token()]);
        self::assertSame(403, $scope->status);
        self::assertSame('Bearer realm="orders", error="insufficient_scope", scope="orders:write"', $scope->header('www-authenticate'));
        self::assertSame(200, self::send('GET', '/protected/write', ['authorization' => 'Bearer ' . self::token(['scope' => 'orders:write'])])->status);
    }

    public function testIntrospectionAndAdminClientsOverRealHttp(): void
    {
        $i = new Introspector(
            endpoint: self::$server->url . '/introspect',
            clientId: 'orders-api:rs',
            clientSecret: 'pa_cs_s3cr3t+/= &x',
            issuer: 'https://id.test/realms/main',
            audience: 'https://api.test/orders',
        );
        self::assertSame('usr_1', $i->authenticate('pa_at_live+1')->subject);
        self::assertVerifierError(E::Inactive, static fn () => $i->authenticate('pa_at_other'));
        $wrong = new Introspector(endpoint: self::$server->url . '/introspect', clientId: 'orders-api:rs', clientSecret: 'nope', issuer: 'https://id.test/realms/main', audience: 'https://api.test/orders');
        self::assertVerifierError(E::Unavailable, static fn () => $wrong->authenticate('pa_at_live+1'));

        $deprecated = [];
        $admin = new AdminClient(baseUrl: self::$server->url, realm: 'main', token: 'admin-token', onDeprecated: static function (string $m, string $p, string $d) use (&$deprecated): void {
            $deprecated[] = "{$m} {$p} {$d}";
        });
        $created = $admin->createClient(['client_id' => 'svc']);
        self::assertInstanceOf(Secret::class, $created['client_secret']);
        self::assertSame('pa_cs_from_server', $created['client_secret']->reveal());
        self::assertSame(['client_id' => 'svc'], $created['client']);
        self::assertSame(['POST /clients @1767225600'], $deprecated);
        $e = self::assertThrows(ProblemException::class, static fn () => $admin->createUser(['email' => 'dup@example.test']));
        self::assertSame('conflict', $e->errorCode);
        self::assertSame('req_srv', $e->requestId);
        self::assertSame('identifier already in use', $e->detail);
    }
}

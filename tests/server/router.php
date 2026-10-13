<?php

declare(strict_types=1);

/*
 * Router for `php -S` in HttpIntegrationTest: a few endpoints that exercise
 * CurlTransport, plus resource-server, introspection and admin endpoints built
 * with the SDK itself.
 */

require __DIR__ . '/../bootstrap.php';

use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Middleware\RequestAuthenticator;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\Verifier;

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

function json_out(int $status, mixed $body, array $headers = []): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    foreach ($headers as $h) {
        header($h, false);
    }
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
}

switch (true) {
    case $path === '/echo':
        $headers = [];
        foreach (getallheaders() as $k => $v) {
            $headers[strtolower($k)] = $v;
        }
        json_out(200, [
            'method' => $_SERVER['REQUEST_METHOD'],
            'uri' => $_SERVER['REQUEST_URI'],
            'headers' => $headers,
            'body' => file_get_contents('php://input'),
        ], ['X-Multi: a', 'X-Multi: b', 'ETag: "e1"']);
        return;

    case preg_match('#^/status/(\d{3})$#', $path, $m) === 1:
        json_out((int) $m[1], ['status' => (int) $m[1]]);
        return;

    case $path === '/redirect':
        header('Location: /echo', true, 307);
        return;

    case $path === '/slow':
        usleep(1_500_000);
        echo 'late';
        return;

    case $path === '/big-declared':
        header('Content-Length: 5000000');
        echo str_repeat('x', 1000);
        return;

    case $path === '/big-streamed':
        for ($i = 0; $i < 64; $i++) {
            echo str_repeat('y', 64 * 1024);
            flush();
        }
        return;

    case $path === '/introspect':
        // PHP decodes Basic credentials but does not form-decode them (RFC 6749 §2.3.1).
        $user = urldecode($_SERVER['PHP_AUTH_USER'] ?? '');
        $pass = urldecode($_SERVER['PHP_AUTH_PW'] ?? '');
        $token = $_POST['token'] ?? '';
        if ($user !== 'orders-api:rs' || $pass !== 'pa_cs_s3cr3t+/= &x') {
            json_out(401, ['error' => 'invalid_client']);
            return;
        }
        json_out(200, $token === 'pa_at_live+1' ? [
            'active' => true, 'iss' => 'https://id.test/realms/main', 'aud' => 'https://api.test/orders', 'sub' => 'usr_1',
            'client_id' => 'web', 'token_kind' => 'user_access', 'scope' => 'orders:read', 'exp' => time() + 300,
        ] : ['active' => false]);
        return;

    case str_starts_with($path, '/api/v1/realms/main/'):
        if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer admin-token' || ($_SERVER['HTTP_PROUDAUTH_SDK'] ?? '') !== 'php/0.2.0') {
            json_out(401, ['code' => 'unauthenticated', 'title' => 'Unauthenticated']);
            return;
        }
        $body = json_decode((string) file_get_contents('php://input'), true);
        if ($path === '/api/v1/realms/main/clients') {
            json_out(201, ['client' => ['client_id' => $body['client_id'] ?? ''], 'client_secret' => 'pa_cs_from_server'], ['Deprecation: @1767225600']);
            return;
        }
        http_response_code(409);
        header('Content-Type: application/problem+json');
        header('X-Request-Id: req_srv');
        echo json_encode(['code' => 'conflict', 'title' => 'Conflict', 'detail' => 'identifier already in use']);
        return;

    case str_starts_with($path, '/protected'):
        $jwks = (string) file_get_contents((string) getenv('PROUDAUTH_TEST_JWKS'));
        $verifier = new Verifier(
            issuer: 'https://id.test/realms/main',
            audience: 'https://api.test/orders',
            jwksUrl: 'https://id.test/realms/main/jwks',
            transport: new FakeTransport(static fn (): Response => new Response(200, ['content-type' => 'application/json'], $jwks)),
        );
        $auth = new RequestAuthenticator($verifier, realm: 'orders');
        $auth->protect(static function (Claims $claims) use ($path): void {
            if ($path === '/protected/write') {
                $claims->requireScope('orders:write');
            }
            header('Content-Type: application/json');
            echo json_encode(['subject' => $claims->subject]);
        });
        return;

    default:
        json_out(404, ['code' => 'not_found']);
}

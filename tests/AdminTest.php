<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Admin\AdminClient;
use ProudAuth\Sdk\Admin\AdminErrorCode;
use ProudAuth\Sdk\Admin\AdminRequestException;
use ProudAuth\Sdk\Admin\ProblemException;
use ProudAuth\Sdk\Admin\RequestOptions;
use ProudAuth\Sdk\Admin\Secret;
use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Http\TransportException;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Version;

/**
 * Port of sdk/node/test/admin.test.ts.
 */
final class AdminTest extends TestCase
{
    private const TOKEN = 'pa_at_admin_secret_token';
    private const PREFIX = '/api/v1/realms/main%20realm';

    private FakeTransport $api;

    protected function setUp(): void
    {
        $this->api = new FakeTransport(fn (Request $r): Response => $this->handle($r));
    }

    private function handle(Request $r): Response
    {
        $u = parse_url($r->url);
        self::assertSame('https', $u['scheme']);
        self::assertSame('api.test', $u['host']);
        $p = substr($u['path'], strlen(self::PREFIX));
        $q = Query::parse($u['query'] ?? '');
        $m = $r->method;
        if ($r->header('authorization') !== 'Bearer ' . self::TOKEN) {
            return FakeTransport::json(401, ['code' => 'unauthenticated', 'title' => 'Unauthenticated']);
        }
        if ($p === '/users' && $m === 'GET') {
            $pages = [
                '' => ['items' => [['id' => 'u1'], ['id' => 'u2']], 'next_cursor' => 'c1'],
                'c1' => ['items' => [['id' => 'u3']], 'next_cursor' => 'c2'],
                'c2' => ['items' => [['id' => 'u4']], 'next_cursor' => ''],
            ];
            return FakeTransport::json(200, $pages[$q->getAll('cursor')[0] ?? '']);
        }
        if ($p === '/organizations' && $m === 'GET') {
            return FakeTransport::json(200, ['items' => [['id' => 'o1']], 'next_cursor' => 'loop']);
        }
        if ($p === '/clients' && $m === 'POST') {
            return FakeTransport::json(201, [
                'client' => ['client_id' => 'web'], 'client_secret' => 'pa_cs_once', 'recovery_codes' => ['aaaa-bbbb'],
                'nested' => ['webhook_secrets' => [['id' => 'w1', 'value' => 'whsec_1']]], 'token_count' => 2,
            ], ['deprecation' => '@1767225600', 'sunset' => 'Wed, 01 Jul 2026 00:00:00 GMT']);
        }
        if ($p === '/users' && $m === 'POST') {
            $input = json_decode((string) $r->body, true);
            if (($input['email'] ?? '') === 'dup@example.test') {
                return FakeTransport::json(409, ['type' => 'about:blank', 'code' => 'conflict', 'title' => 'Conflict', 'detail' => 'identifier already in use', 'errors' => ['email' => 'taken'], 'request_id' => 'req_1', 'retryable' => false], ['content-type' => 'application/problem+json']);
            }
            return FakeTransport::json(201, ['id' => 'u9', 'setup_token' => 'pa_inv_once']);
        }
        if ($p === '/users/u%2F1' && $m === 'GET') {
            return FakeTransport::json(200, ['id' => 'u/1', 'version' => 3], ['etag' => '"v3"']);
        }
        if ($p === '/users/u%2F1' && $m === 'PATCH') {
            if ($r->header('if-match') !== '"v3"') {
                return FakeTransport::json(412, ['code' => 'precondition_failed', 'title' => 'Stale']);
            }
            return FakeTransport::json(200, ['id' => 'u/1', 'version' => 4], ['etag' => '"v4"']);
        }
        if ($p === '/users/u1/revoke-sessions') {
            return FakeTransport::json(200, ['revoked_sessions' => 3]);
        }
        if ($p === '/organizations/o1/invitations/batch' && $m === 'POST') {
            return FakeTransport::json(200, ['results' => [['index' => 0, 'status' => 201]]]);
        }
        if ($p === '/slow') {
            throw new TransportException(TransportException::TIMEOUT, 'deadline exceeded');
        }
        if ($p === '/empty') {
            return new Response(204);
        }
        if ($p === '/teapot') {
            return new Response(503, ['x-request-id' => 'req_h'], 'upstream exploded');
        }
        if ($p === '/garbage') {
            return new Response(200, [], 'not json');
        }
        if ($p === '/moved') {
            return new Response(308, ['location' => 'https://elsewhere.test/']);
        }
        if ($p === '/deprecated-error') {
            return FakeTransport::json(410, ['code' => 'gone', 'title' => 'Gone'], ['deprecation' => 'true']);
        }
        if (str_starts_with($p, '/echo')) {
            return FakeTransport::json(200, ['items' => [['id' => 'x']], 'results' => [], 'next_cursor' => '', 'revoked_sessions' => 0]);
        }
        return FakeTransport::json(404, ['code' => 'not_found', 'title' => 'Not Found']);
    }

    /** @param array<string, mixed> $over */
    private function admin(array $over = []): AdminClient
    {
        return new AdminClient(...array_merge(['baseUrl' => 'https://api.test/', 'realm' => 'main realm', 'token' => self::TOKEN, 'userAgent' => 'sdk-test', 'transport' => $this->api], $over));
    }

    public function testIteratesEveryPageWithOpaqueCursors(): void
    {
        $ids = [];
        foreach ($this->admin()->users('ann') as $u) {
            $ids[] = $u['id'];
        }
        self::assertSame(['u1', 'u2', 'u3', 'u4'], $ids);
        $paths = array_map(static fn (Request $r): string => (string) parse_url($r->url, PHP_URL_PATH) . '?' . parse_url($r->url, PHP_URL_QUERY), $this->api->requests);
        self::assertSame(self::PREFIX . '/users?q=ann&cursor=c2', end($paths));
        $pages = iterator_to_array($this->admin()->pages('/users'), false);
        self::assertCount(3, $pages);
        self::assertSame('c1', $pages[0]->nextCursor);
        self::assertSame('', $pages[2]->nextCursor);
    }

    public function testStopsOnACursorLoopInsteadOfSpinning(): void
    {
        $e = self::assertThrows(AdminRequestException::class, function (): void {
            foreach ($this->admin()->organizations() as $_) {
                // drain
            }
        });
        self::assertSame(AdminErrorCode::InvalidResponse, $e->errorCode);
        self::assertSame('admin: GET /organizations failed (invalid_response)', $e->getMessage());
    }

    public function testReturnsTypedRfc9457Problems(): void
    {
        $e = self::assertThrows(ProblemException::class, fn () => $this->admin()->createUser(['email' => 'dup@example.test']));
        self::assertSame(409, $e->status);
        self::assertSame(409, $e->getCode());
        self::assertSame('conflict', $e->errorCode);
        self::assertSame('Conflict', $e->title);
        self::assertSame('identifier already in use', $e->detail);
        self::assertSame(['email' => 'taken'], $e->errors);
        self::assertSame('req_1', $e->requestId);
        self::assertSame('about:blank', $e->type);
        self::assertNull($e->instance);
        self::assertFalse($e->extra['retryable']);
        self::assertSame('application/problem+json', $e->header('content-type'));
        self::assertSame('409 conflict: Conflict (identifier already in use) [email: taken]', $e->getMessage());
        self::assertStringNotContains(self::TOKEN, $e->getMessage());
        $t = self::assertThrows(ProblemException::class, fn () => $this->admin()->request('GET', '/teapot'));
        self::assertSame('Service Unavailable', $t->errorCode);
        self::assertSame('req_h', $t->requestId);
        self::assertSame('503 Service Unavailable: ', $t->getMessage());
        $u = self::assertThrows(ProblemException::class, fn () => $this->admin(['token' => 'wrong'])->request('GET', '/users'));
        self::assertSame(401, $u->status);
        self::assertSame('unauthenticated', $u->errorCode);
    }

    public function testSendsIdempotencyKeysOnCreates(): void
    {
        $this->admin()->createUser(['email' => 'a@example.test']);
        $first = $this->api->last();
        self::assertMatches('/^[0-9a-f]{32}$/', (string) $first->header('idempotency-key'));
        self::assertSame('application/json', $first->header('content-type'));
        self::assertSame('application/json, application/problem+json', $first->header('accept'));
        self::assertSame('sdk-test proudauth-sdk-php/' . Version::SDK_VERSION, $first->header('user-agent'));
        self::assertSame('{"email":"a@example.test"}', $first->body);
        $this->admin()->createUser(['email' => 'a@example.test'], new RequestOptions(idempotencyKey: 'retry-key-1'));
        self::assertSame('retry-key-1', $this->api->last()->header('idempotency-key'));
        $this->admin()->request('GET', '/echo');
        self::assertNull($this->api->last()->header('idempotency-key'), 'no key on reads');
        self::assertNull($this->api->last()->header('content-type'), 'no content type without a body');
        self::assertNull($this->api->last()->body);
    }

    public function testKeepsTheGeneratedIdempotencyKeyForBatchInvitationsWhenTheOptionIsNull(): void
    {
        $results = $this->admin()->inviteBatch('o1', [['email' => 'a@example.test']], new RequestOptions(idempotencyKey: null));
        self::assertSame([['index' => 0, 'status' => 201]], $results);
        self::assertMatches('/^[0-9a-f]{32}$/', (string) $this->api->last()->header('idempotency-key'));
        $this->admin()->inviteBatch('o1', []);
        self::assertMatches('/^[0-9a-f]{32}$/', (string) $this->api->last()->header('idempotency-key'));
        self::assertSame('{"items":[]}', $this->api->last()->body);
        $this->admin()->inviteBatch('o1', [], new RequestOptions(idempotencyKey: 'batch-retry-1'));
        self::assertSame('batch-retry-1', $this->api->last()->header('idempotency-key'));
    }

    public function testSupportsIfMatchWithEtagsAndEscapesPathIdentifiers(): void
    {
        $a = $this->admin();
        $got = $a->getUser('u/1');
        self::assertSame('"v3"', $got->etag);
        self::assertSame(['id' => 'u/1', 'version' => 3], $got->data);
        $upd = $a->updateUser('u/1', ['display_name' => 'Ann'], new RequestOptions(ifMatch: $got->etag));
        self::assertSame('"v4"', $upd->etag);
        self::assertSame('"v3"', $this->api->last()->header('if-match'));
        $e = self::assertThrows(ProblemException::class, static fn () => $a->updateUser('u/1', ['display_name' => 'Ann'], new RequestOptions(ifMatch: '"v1"')));
        self::assertSame(412, $e->status);
        self::assertThrows(\InvalidArgumentException::class, static fn () => $a->getUser(''), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'non-empty'));
    }

    public function testEnforcesDeadlinesAndReportsTransportFailures(): void
    {
        $e = self::assertThrows(AdminRequestException::class, fn () => $this->admin(['timeoutMs' => 50])->request('GET', '/slow'));
        self::assertSame(AdminErrorCode::Timeout, $e->errorCode);
        self::assertSame(50, $this->api->last()->timeoutMs);
        $this->admin()->request('GET', '/echo', null, new RequestOptions(timeoutMs: 1234));
        self::assertSame(1234, $this->api->last()->timeoutMs);
        self::assertSame(32 << 20, $this->api->last()->maxResponseBytes);
        $e = self::assertThrows(AdminRequestException::class, fn () => $this->admin()->request('GET', '/moved'));
        self::assertSame(AdminErrorCode::Network, $e->errorCode, 'redirects are not followed');
        $e = self::assertThrows(AdminRequestException::class, fn () => $this->admin()->request('GET', '/garbage?q=secret@example.test'));
        self::assertSame(AdminErrorCode::InvalidResponse, $e->errorCode);
        self::assertSame('/garbage', $e->path);
        self::assertStringNotContains('secret@example.test', $e->getMessage());
        $big = new FakeTransport(static fn (): Response => FakeTransport::json(200, ['pad' => str_repeat('x', 2000)]));
        $e = self::assertThrows(AdminRequestException::class, fn () => $this->admin(['transport' => $big, 'maxResponseBytes' => 1000])->request('GET', '/echo'));
        self::assertSame(AdminErrorCode::Network, $e->errorCode);
    }

    public function testUsesTokenSourcesHandlesEmptyBodiesAndValidatesInput(): void
    {
        $calls = 0;
        $a = $this->admin(['token' => static function () use (&$calls): string {
            $calls++;
            return self::TOKEN;
        }]);
        self::assertSame(3, $a->revokeSessions('u1'));
        self::assertSame('{}', $this->api->last()->body);
        $empty = $a->request('POST', '/empty', []);
        self::assertSame(204, $empty->status);
        self::assertNull($empty->data);
        self::assertSame('{}', $this->api->last()->body, 'an empty array is sent as an empty object');
        self::assertSame(2, $calls);
        self::assertThrows(\InvalidArgumentException::class, static fn () => $a->setUserState('u1', 'delete', 'x'), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'unknown user state action'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => $a->request('GET', 'users'), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'must start'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => $a->request('POST', '/users', ['x' => "\xff"]), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'JSON-encodable'));
        $e = self::assertThrows(AdminRequestException::class, fn () => $this->admin(['token' => static fn (): string => throw new \RuntimeException('vault down')])->request('GET', '/users'));
        self::assertSame(AdminErrorCode::TokenSource, $e->errorCode);
        self::assertSame('vault down', $e->getPrevious()?->getMessage());
        self::assertThrows(\InvalidArgumentException::class, static fn () => new AdminClient(baseUrl: 'not a url', realm: 'r'), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'absolute URL'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => new AdminClient(baseUrl: 'https://x.test', realm: ''), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'realm is required'));
        $none = $this->admin(['token' => null]);
        self::assertThrows(ProblemException::class, static fn () => $none->request('GET', '/users'));
        self::assertNull($this->api->last()->header('authorization'));
    }

    public function testNeverIncludesRequestBodiesOrTokensInTransportErrors(): void
    {
        $dead = new AdminClient(baseUrl: 'http://127.0.0.1:1', realm: 'main', token: self::TOKEN, timeoutMs: 2000);
        $e = self::assertThrows(AdminRequestException::class, static fn () => $dead->createUser(['password' => 'hunter2']));
        self::assertSame(AdminErrorCode::Network, $e->errorCode);
        $all = $e->getMessage() . ' ' . $e->getPrevious()?->getMessage();
        self::assertStringNotContains('hunter2', $all);
        self::assertStringNotContains(self::TOKEN, $all);
        self::assertStringNotContains(self::TOKEN, print_r($dead, true));
    }

    public function testWrapsOneTimeSecretsSendsItsVersionAndReportsDeprecation(): void
    {
        $notes = [];
        $a = $this->admin(['userAgent' => 'tool/1', 'onDeprecated' => static function (string $method, string $path, string $deprecation, ?string $sunset) use (&$notes): void {
            $notes[] = "{$method} {$path} {$deprecation} {$sunset}";
        }]);
        $res = $a->request('POST', '/clients?trace=1', []);
        $secret = $res->data['client_secret'];
        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame('pa_cs_once', $secret->reveal());
        self::assertInstanceOf(Secret::class, $res->data['recovery_codes'][0]);
        self::assertSame('aaaa-bbbb', $res->data['recovery_codes'][0]->reveal());
        self::assertInstanceOf(Secret::class, $res->data['nested']['webhook_secrets'][0]['value']);
        self::assertSame(2, $res->data['token_count'], 'only exact member names are secrets');
        ob_start();
        var_dump($res->data);
        $dumped = (string) ob_get_clean();
        $shown = implode(' ', [(string) $secret, json_encode($res->data), print_r($res->data, true), $dumped, var_export($res->data, true), "{$secret}", json_encode((array) $secret)]);
        foreach (['pa_cs_once', 'aaaa-bbbb', 'whsec_1'] as $value) {
            self::assertStringNotContains($value, $shown);
        }
        self::assertStringContains('[REDACTED]', $shown);
        self::assertThrows(\LogicException::class, static fn () => serialize($res->data));
        self::assertThrows(\Error::class, static fn () => clone $secret);
        self::assertSame('', (string) new Secret(''));
        self::assertSame(['client_id' => 'web'], $res->data['client']);
        self::assertSame('@1767225600', $res->deprecation);
        self::assertSame('Wed, 01 Jul 2026 00:00:00 GMT', $res->sunset);
        self::assertSame(['POST /clients @1767225600 Wed, 01 Jul 2026 00:00:00 GMT'], $notes);
        $sent = $this->api->last();
        self::assertSame('php/' . Version::SDK_VERSION, $sent->header('proudauth-sdk'));
        self::assertSame('tool/1 proudauth-sdk-php/' . Version::SDK_VERSION, $sent->header('user-agent'));
        self::assertSame(AdminClient::SDK_VERSION, '0.2.0');
        self::assertThrows(ProblemException::class, static fn () => $a->request('DELETE', '/deprecated-error?x=1'));
        self::assertSame('DELETE /deprecated-error true ', end($notes), 'error responses are reported too');
        $this->admin()->createUser(['email' => 'a@example.test']);
        self::assertSame('pa_inv_once', $this->admin()->createUser(['email' => 'b@example.test'])['setup_token']->reveal());
    }

    public function testTypedHelpersCallTheDocumentedRoutes(): void
    {
        $a = $this->admin(['baseUrl' => 'https://api.test', 'realm' => 'main realm']);
        $route = function (\Closure $call, string $method, string $path, ?string $body = null): void {
            $result = $call();
            if ($result instanceof \Generator) {
                iterator_to_array($result, false);
            }
            $r = $this->api->last();
            $u = parse_url($r->url);
            self::assertSame($method, $r->method, $path);
            self::assertSame(self::PREFIX . $path, $u['path'] . (isset($u['query']) ? '?' . $u['query'] : ''));
            if ($body !== null) {
                self::assertSame($body, $r->body, $path);
            }
        };
        // Route everything to the catch-all echo handler.
        $echo = new FakeTransport(static fn (): Response => FakeTransport::json(200, ['items' => [['id' => 'x']], 'results' => [], 'next_cursor' => '']));
        $this->api = $echo;
        $a = $this->admin(['transport' => $echo]);
        $route(static fn () => $a->organizations(), 'GET', '/organizations');
        $route(static fn () => $a->createOrganization('acme', 'Acme'), 'POST', '/organizations', '{"slug":"acme","display_name":"Acme"}');
        $route(static fn () => $a->members('o 1'), 'GET', '/organizations/o%201/members');
        $route(static fn () => $a->addMember('o1', 'u1', ['r1']), 'POST', '/organizations/o1/members', '{"user_id":"u1","role_ids":["r1"]}');
        $route(static fn () => $a->invite('o1', 'a@example.test', ['r1']), 'POST', '/organizations/o1/invitations', '{"email":"a@example.test","role_ids":["r1"]}');
        self::assertMatches('/^[0-9a-f]{32}$/', (string) $echo->last()->header('idempotency-key'));
        $route(static fn () => $a->roles('organization'), 'GET', '/roles?boundary_type=organization');
        self::assertSame([['id' => 'x']], $a->roles('organization'));
        $route(static fn () => $a->assign('r1', ['type' => 'user', 'id' => 'u1'], ['type' => 'organization', 'id' => 'o1']), 'POST', '/role-assignments', '{"role_id":"r1","subject":{"type":"user","id":"u1"},"scope":{"type":"organization","id":"o1"}}');
        $route(static fn () => $a->createClient(['client_id' => 'svc']), 'POST', '/clients', '{"client_id":"svc"}');
        $route(static fn () => $a->rotateClientSecret('cli_1', 3600), 'POST', '/clients/cli_1/credentials', '{"retire_others_after_seconds":3600}');
        $route(static fn () => $a->requestImpersonation(['reason' => 'ticket 1']), 'POST', '/impersonation-requests', '{"reason":"ticket 1"}');
        $route(static fn () => $a->issueImpersonation('req_1'), 'POST', '/impersonation-requests/req_1/issue');
        self::assertNull($echo->last()->body);
        $route(static fn () => $a->revokeImpersonation('imp_1', 'done'), 'POST', '/impersonation-grants/imp_1/revoke', '{"reason":"done"}');
        $route(static fn () => $a->clients(), 'GET', '/clients');
        $route(static fn () => $a->setResourceGrant('cli_1', 'res_1', ['orders:read'], ['user']), 'PUT', '/clients/cli_1/resource-grants/res_1', '{"allowed_scopes":["orders:read"],"subject_types":["user"]}');
        $route(static fn () => $a->userSessions('u1'), 'GET', '/users/u1/sessions');
        $route(static fn () => $a->revokeSession('u1', 'ses_1'), 'DELETE', '/users/u1/sessions/ses_1');
        $route(static fn () => $a->invitations('o1', 'pending'), 'GET', '/organizations/o1/invitations?state=pending');
        $route(static fn () => $a->revokeInvitation('o1', 'inv_1'), 'POST', '/organizations/o1/invitations/inv_1/revoke');
        $route(static fn () => $a->impersonationGrants(['state' => 'active', 'actor_user_id' => 'u 1']), 'GET', '/impersonation-grants?state=active&actor_user_id=u+1');
        $route(static fn () => $a->subjectPermissions('usr_1', 'org_1'), 'GET', '/subjects/usr_1/permissions?organization_id=org_1');
        $route(static fn () => $a->subjectPermissions('usr_1'), 'GET', '/subjects/usr_1/permissions');
        $route(static fn () => $a->auditEvents(['type' => 'user.created']), 'GET', '/audit-events?type=user.created');
        $route(static fn () => $a->setUserState('u1', 'suspend', 'fraud'), 'POST', '/users/u1/suspend', '{"reason":"fraud"}');
        $route(static fn () => $a->users(), 'GET', '/users?q=');
        self::assertSame(32, strlen(AdminClient::newIdempotencyKey()));
    }
}

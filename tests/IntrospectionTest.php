<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Http\TransportException;
use ProudAuth\Sdk\Introspection\Introspector;
use ProudAuth\Sdk\Introspection\SupportAuditor;
use ProudAuth\Sdk\Introspection\SupportEvent;
use ProudAuth\Sdk\Introspection\SupportGuard;
use ProudAuth\Sdk\Introspection\SupportOperations;
use ProudAuth\Sdk\Middleware\RequestAuthenticator;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;

/**
 * Port of sdk/node/test/introspection.test.ts.
 */
final class IntrospectionTest extends TestCase
{
    private const ISS = 'https://id.test/realms/main';
    private const AUD = 'https://api.test/orders';
    private const ENDPOINT = 'https://id.test/realms/main/oauth/introspect';
    private const CLIENT_ID = 'orders-api:rs';
    private const CLIENT_SECRET = 'pa_cs_s3cr3t+/= &x';

    /** @var array<string, array<string, mixed>|\Closure(int): mixed> */
    private array $tokens = [];
    private string $mode = 'ok';
    private int $introspections = 0;
    private ?Request $last = null;
    private FakeTransport $idp;

    protected function setUp(): void
    {
        $this->idp = new FakeTransport(function (Request $r): Response {
            if ($r->method !== 'POST' || $r->url !== self::ENDPOINT) {
                return FakeTransport::json(404, []);
            }
            $this->introspections++;
            $this->last = $r;
            switch ($this->mode) {
                case 'error':
                    return FakeTransport::json(500, ['error' => 'server_error']);
                case 'slow':
                    throw new TransportException(TransportException::TIMEOUT, 'deadline exceeded');
                case 'network':
                    throw new TransportException(TransportException::NETWORK, 'connection refused');
                case 'garbage':
                    return FakeTransport::json(200, '<html>');
                case 'dup':
                    return FakeTransport::json(200, '{"active":false,"active":true,"iss":"' . self::ISS . '"}');
                case 'array':
                    return FakeTransport::json(200, '[{"active":true}]');
                case 'redirect':
                    return new Response(307, ['location' => 'https://elsewhere.test/introspect']);
                case 'huge':
                    return FakeTransport::json(200, ['active' => true, 'pad' => str_repeat('x', 70_000)]);
            }
            $tok = FakeTransport::form($r->body)['token'] ?? '';
            $entry = $this->tokens[$tok] ?? null;
            $v = $entry instanceof \Closure ? $entry($this->introspections) : $entry;
            return FakeTransport::json(200, $v ?? ['active' => false]);
        });
    }

    /** @param array<string, mixed> $over */
    private function intro(array $over = []): Introspector
    {
        return new Introspector(...array_merge([
            'endpoint' => self::ENDPOINT,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'issuer' => self::ISS,
            'audience' => self::AUD,
            'timeoutMs' => 150,
            'transport' => $this->idp,
        ], $over));
    }

    /** @return array<string, mixed> */
    private static function active(array $extra = []): array
    {
        return array_merge([
            'active' => true,
            'iss' => self::ISS,
            'sub' => 'usr_1',
            'aud' => self::AUD,
            'client_id' => 'web',
            'scope' => 'orders:read',
            'exp' => 1_800_000_300,
            'iat' => 1_800_000_000,
            'jti' => 'tok_1',
            'sid' => 'ses_1',
            'org_id' => 'org_a',
            'token_kind' => 'user_access',
            'token_type' => 'Bearer',
            'authz_version' => 7,
        ], $extra);
    }

    /** @return array<string, mixed> */
    private static function support(array $extra = []): array
    {
        return self::active(array_merge([
            'sub' => 'usr_customer',
            'client_id' => 'support-bff',
            'jti' => 'tok_support_1',
            'token_kind' => 'impersonation_access',
            'act' => ['iss' => self::ISS, 'sub' => 'usr_agent'],
            'impersonation_grant_id' => 'imp_1',
            'support_mode' => 'read_only',
        ], $extra));
    }

    public function testAuthenticatesWithClientSecretBasicAndFormEncodedCredentials(): void
    {
        $this->tokens['pa_at_abc'] = self::active();
        $c = $this->intro()->authenticate('pa_at_abc');
        self::assertSame('usr_1', $c->subject);
        self::assertTrue($c->online);
        self::assertSame(7, $c->authzVersion);
        self::assertSame(1_800_000_300, $c->expiry?->getTimestamp());
        self::assertSame(['orders:read'], $c->scopes);
        $r = $this->last;
        self::assertSame('application/x-www-form-urlencoded', $r?->header('content-type'));
        self::assertSame('application/json', $r?->header('accept'));
        self::assertSame('token=pa_at_abc', $r?->body);
        self::assertSame(150, $r?->timeoutMs);
        self::assertSame(64 << 10, $r?->maxResponseBytes);
        $decoded = (string) base64_decode(substr((string) $r?->header('authorization'), strlen('Basic ')));
        self::assertSame('orders-api%3Ars:pa_cs_s3cr3t%2B%2F%3D+%26x', $decoded);
        [$id, $secret] = array_map('urldecode', explode(':', $decoded));
        self::assertSame(self::CLIENT_ID, $id);
        self::assertSame(self::CLIENT_SECRET, $secret);
    }

    public function testRefusesSenderBoundOpaqueTokensThroughTokenOnlyIntrospection(): void
    {
        foreach ([['jkt' => str_repeat('x', 43)], ['x5t#S256' => str_repeat('x', 43)], null, [], ['unknown' => 'binding']] as $cnf) {
            $this->tokens['bound'] = self::active(['cnf' => $cnf]);
            self::assertVerifierError(E::SenderConstraint, fn () => $this->intro()->authenticate('bound'));
        }
    }

    public function testAcceptsJwtAccessTokensTooFormEncodingTheToken(): void
    {
        $this->tokens['a.b+c.d'] = self::active();
        $this->intro()->authenticate('a.b+c.d');
        self::assertSame('token=a.b%2Bc.d', $this->last?->body);
    }

    public function testDeniesInactiveTokens(): void
    {
        $this->tokens['t'] = ['active' => false];
        self::assertVerifierError(E::Inactive, fn () => $this->intro()->authenticate('t'));
        $this->tokens['t2'] = ['active' => 'true', 'iss' => self::ISS, 'aud' => self::AUD, 'token_kind' => 'user_access'];
        self::assertVerifierError(E::Inactive, fn () => $this->intro()->authenticate('t2'));
        self::assertVerifierError(E::Inactive, fn () => $this->intro()->authenticate('unknown'));
    }

    public function testNeverCachesARevocationIsVisibleOnTheNextRequest(): void
    {
        $revoked = false;
        $this->tokens['t'] = static function () use (&$revoked): array {
            return $revoked ? ['active' => false] : self::active();
        };
        $i = $this->intro();
        $before = $this->introspections;
        $i->authenticate('t');
        $i->authenticate('t');
        $revoked = true;
        self::assertVerifierError(E::Inactive, static fn () => $i->authenticate('t'));
        self::assertSame(3, $this->introspections - $before);
    }

    public function testFailsClosedOnHttpErrorsBadJsonTimeoutsAndNetworkErrors(): void
    {
        $this->tokens['t'] = self::active();
        foreach (['error', 'garbage', 'dup', 'array', 'slow', 'network', 'redirect', 'huge'] as $mode) {
            $this->mode = $mode;
            $e = self::assertVerifierError(E::Unavailable, fn () => $this->intro()->authenticate('t'), $mode);
            self::assertSame('verifier: verification dependency unavailable', $e->getMessage());
        }
        $this->mode = 'ok';
        $dead = new Introspector(endpoint: 'http://127.0.0.1:1/oauth/introspect', clientId: 'rs', clientSecret: 's', issuer: self::ISS, audience: self::AUD, timeoutMs: 500);
        self::assertVerifierError(E::Unavailable, static fn () => $dead->authenticate('t'));
    }

    public function testChecksIssuerAndAudienceOfTheIntrospectionResult(): void
    {
        $this->tokens['t1'] = self::active(['iss' => 'https://other.test']);
        self::assertVerifierError(E::Issuer, fn () => $this->intro()->authenticate('t1'));
        $this->tokens['t2'] = self::active(['aud' => 'https://api.test/billing']);
        self::assertVerifierError(E::Audience, fn () => $this->intro()->authenticate('t2'));
        $this->tokens['t3'] = self::active(['aud' => [self::AUD, 'https://api.test/billing']]);
        self::assertVerifierError(E::Audience, fn () => $this->intro()->authenticate('t3'));
        $this->tokens['t4'] = self::active(['aud' => [self::AUD]]);
        $this->intro()->authenticate('t4');
        $this->tokens['t5'] = self::active(['iss' => null]);
        self::assertVerifierError(E::Issuer, fn () => $this->intro()->authenticate('t5'));
    }

    public function testRejectsSupportTokensOnOrdinaryPaths(): void
    {
        $this->tokens['pa_it_1'] = self::active(['token_kind' => 'impersonation_access', 'act' => ['sub' => 'usr_agent'], 'impersonation_grant_id' => 'imp_1']);
        self::assertVerifierError(E::TokenKind, fn () => $this->intro()->authenticate('pa_it_1'));
        $this->tokens['x'] = self::active(['token_kind' => 'refresh']);
        self::assertVerifierError(E::TokenKind, fn () => $this->intro()->authenticate('x'));
        $this->tokens['k'] = self::active(['token_kind' => 'api_key']);
        self::assertSame('api_key', $this->intro()->authenticate('k')->tokenKind);
        self::assertVerifierError(E::TokenKind, fn () => $this->intro(['acceptedKinds' => ['user_access']])->authenticate('k'));
    }

    public function testRejectsMissingAndOversizedTokensWithoutANetworkCall(): void
    {
        $before = $this->introspections;
        self::assertVerifierError(E::MissingToken, fn () => $this->intro()->authenticate(''));
        self::assertVerifierError(E::TooLarge, fn () => $this->intro()->authenticate(str_repeat('x', 9000)));
        self::assertSame($before, $this->introspections);
    }

    public function testParsesClaimsLeniently(): void
    {
        $this->tokens['t'] = self::active(['exp' => 1_800_000_300.9, 'authz_version' => 'x', 'act' => ['sub' => 7, 'act' => ['sub' => 'svc_gw']], 'scope' => null, 'auth_time' => -5]);
        $c = $this->intro()->authenticate('t');
        self::assertSame(1_800_000_300, $c->expiry?->getTimestamp());
        self::assertSame(0, $c->authzVersion);
        self::assertSame('', $c->actor?->subject);
        self::assertSame('svc_gw', $c->actor?->act?->subject);
        self::assertSame([], $c->scopes);
        self::assertNull($c->authTime);
    }

    public function testValidatesConfiguration(): void
    {
        $msg = static fn (string $part): \Closure => static fn (\Throwable $e): bool => str_contains($e->getMessage(), $part);
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['audience' => '']), $msg('audience is required'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['issuer' => '']), $msg('issuer is required'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['clientSecret' => '']), $msg('clientSecret is required'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['clientId' => '']), $msg('clientId is required'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['endpoint' => 'ftp://x']), $msg('http'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['timeoutMs' => 0]), $msg('timeoutMs'));
        self::assertThrows(\InvalidArgumentException::class, fn () => $this->intro(['acceptedKinds' => ['user_access', 'impersonation_access']]), $msg('SupportGuard'));
        $i = $this->intro();
        self::assertFalse(is_callable([$i, 'introspect']), 'the kind-less introspection is not reachable from outside');
        self::assertStringNotContains(self::CLIENT_SECRET, print_r($i, true));
        self::assertStringNotContains('Basic', print_r($i, true));
    }

    // ---------------------------------------------------------------------
    // SupportGuard
    // ---------------------------------------------------------------------

    /**
     * @param list<string> $writeOperations
     *
     * @return array{0: SupportGuard, 1: \ArrayObject<int, SupportEvent>, 2: \ArrayObject<int, string>}
     */
    private function setupGuard(?\Closure $auditor = null, array $writeOperations = ['orders.annotate']): array
    {
        $events = new \ArrayObject();
        $order = new \ArrayObject();
        $guard = new SupportGuard(
            introspector: $this->intro(),
            auditor: $auditor ?? static function (SupportEvent $ev) use ($events, $order): void {
                $order[] = 'audit';
                $events[] = $ev;
            },
            writeOperations: $writeOperations,
        );
        return [$guard, $events, $order];
    }

    public function testSupportGuardRequiresAnAuditorAndAnIntrospector(): void
    {
        self::assertVerifierError(E::Contract, fn () => new SupportGuard($this->intro(), null));
        self::assertVerifierError(E::Contract, static fn () => new SupportGuard(null, static function (): void {
        }));
    }

    public function testSupportGuardAllowsAReadWithActorAttributionAuditingBeforeAccess(): void
    {
        $this->tokens['pa_it_1'] = self::support();
        [$guard, $events, $order] = $this->setupGuard();
        $c = $guard->authorize('pa_it_1', 'orders.list', true);
        $order[] = 'access';
        self::assertSame(['audit', 'access'], $order->getArrayCopy());
        self::assertTrue($c->isSupport());
        self::assertSame('usr_agent', $c->actor?->subject);
        self::assertSame('usr_customer', $c->subject);
        self::assertCount(1, $events->getArrayCopy());
        $ev = $events[0];
        self::assertTrue($ev->allowed);
        self::assertTrue($ev->read);
        self::assertNull($ev->denyReason);
        self::assertSame('usr_agent', $ev->actor);
        self::assertSame(self::ISS, $ev->actorIssuer);
        self::assertSame('usr_customer', $ev->subject);
        self::assertSame('imp_1', $ev->grantId);
        self::assertSame('org_a', $ev->orgId);
        self::assertSame('support-bff', $ev->clientId);
        self::assertSame('orders.list', $ev->operation);
        self::assertSame('tok_support_1', $ev->tokenId);
        self::assertTrue(abs($ev->at->getTimestamp() - time()) < 5);
    }

    public function testSupportGuardDeniesWritesInReadOnlyModeAndAuditsTheDenial(): void
    {
        $this->tokens['pa_it_1'] = self::support();
        [$guard, $events] = $this->setupGuard();
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('pa_it_1', 'orders.annotate', false));
        self::assertCount(1, $events->getArrayCopy());
        self::assertFalse($events[0]->allowed);
        self::assertSame(SupportEvent::DENY_WRITE_NOT_ALLOWLISTED, $events[0]->denyReason);
    }

    public function testSupportGuardTreatsAnOperationWithoutReadAsAWrite(): void
    {
        $this->tokens['pa_it_1'] = self::support();
        [$guard] = $this->setupGuard();
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('pa_it_1', 'orders.list'));
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('pa_it_1', 'orders.list.update', true), 'a write verb makes it a write');
    }

    public function testSupportGuardAllowsOnlyAllowlistedWritesInAllowlistedWriteMode(): void
    {
        $this->tokens['pa_it_w'] = self::support(['support_mode' => 'allowlisted_write']);
        [$guard] = $this->setupGuard();
        $guard->authorize('pa_it_w', 'orders.annotate', false);
        $guard->authorize('pa_it_w', 'Orders.Annotate', false);
        $guard->authorize('pa_it_w', ' orders.annotate ', false);
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('pa_it_w', 'orders.cancel', false));
    }

    public function testSupportGuardAlwaysDeniesProtectedOperationsEvenAllowlisted(): void
    {
        $this->tokens['pa_it_w'] = self::support(['support_mode' => 'allowlisted_write']);
        $ops = ['password.change', 'password.reset', 'mfa.change.totp', 'api_key.create', 'payment', 'refund', 'orders.delete', 'users.password.change', 'DELETE'];
        [$guard, $events] = $this->setupGuard(null, $ops);
        foreach ($ops as $op) {
            self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('pa_it_w', $op, false), $op);
            self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('pa_it_w', $op, true), $op);
        }
        foreach ($events as $e) {
            self::assertFalse($e->allowed);
            self::assertSame(SupportEvent::DENY_PROTECTED_OPERATION, $e->denyReason);
        }
        // A protected segment anywhere in the name counts (same rule as the Go and Node SDKs).
        self::assertTrue(SupportOperations::isProtectedOperation('orders.refund.read'));
        self::assertFalse(SupportOperations::isProtectedOperation('orders.list'));
        self::assertTrue(SupportOperations::isProtectedOperation('refund.read'));
        self::assertTrue(SupportOperations::isProtectedOperation('orders.export', ['orders.export']));
        // Additional protected operations extend the defaults.
        $this->tokens['pa_it_1'] = self::support();
        $guard2 = new SupportGuard($this->intro(), static function (): void {
        }, [], ['orders.export']);
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard2->authorize('pa_it_1', 'orders.export', true));
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard2->authorize('pa_it_1', 'secrets.read', true));
        $guard2->authorize('pa_it_1', 'orders.list', true);
    }

    public function testSupportGuardDeniesWhenTheAuditRecordCannotBeWritten(): void
    {
        $this->tokens['pa_it_1'] = self::support();
        [$guard] = $this->setupGuard(static function (): void {
            throw new \RuntimeException('db down');
        });
        $e = self::assertVerifierError(E::Unavailable, static fn () => $guard->authorize('pa_it_1', 'orders.list', true));
        self::assertSame('db down', $e->getPrevious()?->getMessage());
        $auditor = new class () implements SupportAuditor {
            public int $calls = 0;

            public function recordSupportAccess(SupportEvent $event): void
            {
                $this->calls++;
                throw new \LogicException('disk full');
            }
        };
        $g2 = new SupportGuard($this->intro(), $auditor);
        self::assertVerifierError(E::Unavailable, static fn () => $g2->authorize('pa_it_1', 'orders.list', true));
        self::assertSame(1, $auditor->calls);
    }

    public function testSupportGuardRequiresAPreservedActorAndGrant(): void
    {
        [$guard, $events] = $this->setupGuard();
        $this->tokens['a'] = self::support(['act' => null]);
        self::assertVerifierError(E::TokenKind, static fn () => $guard->authorize('a', 'orders.list', true));
        $this->tokens['b'] = self::support(['act' => ['sub' => '']]);
        self::assertVerifierError(E::TokenKind, static fn () => $guard->authorize('b', 'orders.list', true));
        $this->tokens['c'] = self::support(['impersonation_grant_id' => null]);
        self::assertVerifierError(E::TokenKind, static fn () => $guard->authorize('c', 'orders.list', true));
        $this->tokens['d'] = self::active(['act' => ['sub' => 'usr_agent']]);
        self::assertVerifierError(E::TokenKind, static fn () => $guard->authorize('d', 'orders.list', true));
        self::assertCount(0, $events->getArrayCopy());
    }

    public function testSupportGuardDeniesAfterRevocationAndWhenIntrospectionIsUnavailableWithoutAuditingAccess(): void
    {
        $revoked = false;
        $this->tokens['pa_it_1'] = static function () use (&$revoked): array {
            return $revoked ? ['active' => false] : self::support();
        };
        [$guard, $events] = $this->setupGuard();
        $guard->authorize('pa_it_1', 'orders.list', true);
        $revoked = true;
        self::assertVerifierError(E::Inactive, static fn () => $guard->authorize('pa_it_1', 'orders.list', true));
        $this->mode = 'error';
        self::assertVerifierError(E::Unavailable, static fn () => $guard->authorize('pa_it_1', 'orders.list', true));
        self::assertCount(1, $events->getArrayCopy());
    }

    public function testAuthorizeAnyRoutesByTheAuthoritativeTokenKindWithOneIntrospection(): void
    {
        $this->tokens['pa_at_user'] = self::active();
        $this->tokens['pa_at_disguised'] = self::support(); // the prefix does not matter
        $this->tokens['pa_at_refresh'] = self::active(['token_kind' => 'refresh']);
        [$guard, $events] = $this->setupGuard();
        $before = $this->introspections;
        $u = $guard->authorizeAny('pa_at_user', 'orders.annotate', false);
        self::assertFalse($u->isSupport());
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorizeAny('pa_at_disguised', 'orders.annotate', false));
        $s = $guard->authorizeAny('pa_at_disguised', 'orders.list', true);
        self::assertTrue($s->isSupport());
        self::assertSame(3, $this->introspections - $before);
        self::assertCount(2, $events->getArrayCopy());
        self::assertVerifierError(E::TokenKind, static fn () => $guard->authorizeAny('pa_at_refresh', 'orders.list', true));
    }

    public function testRouteAuthenticatorsAnswerWithDistinctStatuses(): void
    {
        $this->tokens['pa_it_1'] = self::support();
        $this->tokens['pa_at_user'] = self::active();
        [$guard] = $this->setupGuard();
        self::assertThrows(\InvalidArgumentException::class, static fn () => $guard->route(''));
        $call = static function (\ProudAuth\Sdk\Verifier\Authenticator $a, ?string $tok): int {
            $status = 200;
            $ra = new RequestAuthenticator($a, emit: static function (int $s) use (&$status): void {
                $status = $s;
            });
            $server = ['REQUEST_URI' => '/orders'] + ($tok !== null ? ['HTTP_AUTHORIZATION' => 'Bearer ' . $tok] : []);
            $ra->protect(static fn (): string => 'ran', $server);
            return $status;
        };
        $read = $guard->route('orders.list', true);
        $write = $guard->route('orders.annotate', false);
        self::assertSame(200, $call($read, 'pa_it_1'));
        self::assertSame(403, $call($write, 'pa_it_1'));
        self::assertSame(200, $call($write, 'pa_at_user'));
        self::assertSame(401, $call($read, 'pa_at_unknown'));
        self::assertSame(401, $call($read, null));
        $this->mode = 'error';
        self::assertSame(503, $call($read, 'pa_it_1'));
    }
}

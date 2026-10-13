<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\BoundedState\BoundedState;
use ProudAuth\Sdk\BoundedState\BoundedVerifier;
use ProudAuth\Sdk\BoundedState\CursorExpiredException;
use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Http\TransportException;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Internal\Time;
use ProudAuth\Sdk\Middleware\Challenge;
use ProudAuth\Sdk\Tests\Support\Clock;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Port of sdk/node/test/bounded-state.test.ts.
 */
final class BoundedStateTest extends TestCase
{
    private const T0 = 1791626400000; // 2026-10-10T10:00:00Z in ms

    private static function claims(string $subject, string $sessionId, int|float $issuedAtMs, string $orgId = 'org_1'): Claims
    {
        return new Claims(
            issuer: 'https://id.test/realms/main',
            subject: $subject,
            audience: 'https://api.test',
            clientId: 'web',
            scopes: [],
            orgId: $orgId,
            sessionId: $sessionId,
            tokenKind: 'user_access',
            jti: 'j',
            acr: '',
            authzVersion: 0,
            online: false,
            issuedAt: Time::fromUnixSeconds($issuedAtMs / 1000),
        );
    }

    private static function iso(int|float $ms): string
    {
        return Time::fromUnixSeconds($ms / 1000)->format('Y-m-d\TH:i:s.v\Z');
    }

    /** @return array<string, mixed> */
    private static function revoked(string $sessionId, int|float $at): array
    {
        return ['event_type' => 'session.revoked', 'occurred_at' => self::iso($at), 'data' => ['session_id' => $sessionId]];
    }

    /**
     * A fake stream: $handle(cursor) answers [status, body]; the cursor is "now" for from=now.
     *
     * @param \Closure(string): array{0: int, 1: mixed} $handle
     * @param list<string>                               $cursors
     */
    private static function stream(\Closure $handle, ?array &$cursors = null): FakeTransport
    {
        $cursors = [];
        return new FakeTransport(static function (Request $r) use ($handle, &$cursors): Response {
            $q = Query::parse((string) parse_url($r->url, PHP_URL_QUERY));
            $cursor = ($q->getAll('from')[0] ?? null) === 'now' ? 'now' : ($q->getAll('cursor')[0] ?? '');
            $cursors[] = $cursor;
            [$status, $body] = $handle($cursor);
            return FakeTransport::json($status, $body);
        });
    }

    /** @param array<string, mixed> $over */
    private static function state(FakeTransport $t, Clock $clock, array $over = []): BoundedState
    {
        return new BoundedState(...array_merge([
            'baseUrl' => 'https://id.test',
            'realm' => 'main',
            'token' => static fn (): string => 'svc-token',
            'maxStalenessMs' => 60_000,
            'transport' => $t,
            'now' => $clock->fn(),
        ], $over));
    }

    public function testRejectsRevokedSessionsAndSubjectsAndFailsClosedWhenStale(): void
    {
        $clock = new Clock(self::T0);
        $pending = [];
        $t = new FakeTransport(static function (Request $r) use (&$pending): Response {
            $u = parse_url($r->url);
            if (($u['path'] ?? '') !== '/api/v1/realms/main/session-events') {
                return FakeTransport::json(404, []);
            }
            if (str_contains($u['query'] ?? '', 'from=now')) {
                return FakeTransport::json(200, ['events' => [], 'next_cursor' => '10.0']);
            }
            $events = $pending;
            $pending = [];
            return FakeTransport::json(200, ['events' => $events, 'next_cursor' => '11.0']);
        });
        $state = self::state($t, $clock);
        self::assertVerifierError(E::StaleState, static fn () => $state->check(self::claims('usr_bob', 'ses_1', self::T0)), 'not started');
        $state->start();
        self::assertSame('Bearer svc-token', $t->last()->header('authorization'));
        self::assertSame('https://id.test/api/v1/realms/main/session-events?from=now', $t->last()->url);
        $t0 = self::T0 - 1000;
        $state->check(self::claims('usr_bob', 'ses_1', $t0));
        $pending = [
            ['event_type' => 'session.revoked', 'occurred_at' => self::iso(self::T0), 'data' => ['user_id' => 'usr_bob', 'session_id' => 'ses_1']],
            ['event_type' => 'user.suspended', 'occurred_at' => self::iso(self::T0), 'data' => ['user_id' => 'usr_carol']],
            ['event_type' => 'user.recovery_restricted', 'occurred_at' => self::iso(self::T0), 'data' => ['user_id' => 'usr_dave']],
        ];
        $state->sync();
        self::assertSame('https://id.test/api/v1/realms/main/session-events?cursor=10.0&limit=500', $t->last()->url);
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_bob', 'ses_1', $t0)));
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_carol', 'ses_9', $t0)));
        // A token issued after the subject revocation is unaffected.
        $state->check(self::claims('usr_carol', 'ses_9', self::T0 + 1000));
        $state->check(self::claims('usr_alice', 'ses_2', $t0));
        $state->check(self::claims('usr_dave', 'ses_3', $t0)); // recovery_restricted is not a revocation
        $clock->now += 120_000;
        self::assertVerifierError(E::StaleState, static fn () => $state->check(self::claims('usr_alice', 'ses_2', $t0)));
        self::assertSame(503, Challenge::fromThrowable(new VerifierException(E::StaleState))->status);
    }

    public function testWrapsAnAuthenticator(): void
    {
        $clock = new Clock(self::T0);
        $pending = [];
        $t = self::stream(static function (string $cursor) use (&$pending): array {
            if ($cursor === 'now') {
                return [200, ['events' => [], 'next_cursor' => '1']];
            }
            $e = $pending;
            $pending = [];
            return [200, ['events' => $e, 'next_cursor' => '2']];
        });
        $state = self::state($t, $clock);
        $state->start();
        $inner = new class (self::claims('usr_x', 'ses_x', self::T0 - 10)) implements Authenticator {
            public function __construct(private Claims $c)
            {
            }

            public function authenticate(string $raw): Claims
            {
                return $this->c;
            }
        };
        $v = new BoundedVerifier($inner, $state);
        self::assertSame('usr_x', $v->authenticate('raw')->subject);
        $pending = [self::revoked('ses_x', self::T0)];
        $state->sync();
        self::assertVerifierError(E::Revoked, static fn () => $v->authenticate('raw'));
    }

    public function testReadsSubjectIdForRoleUnassignmentAndRefreshReuseForUserSubjectsOnly(): void
    {
        $clock = new Clock(self::T0);
        $at = self::iso(self::T0);
        $t = self::stream(static fn (string $cursor): array => $cursor === 'now'
            ? [200, ['events' => [], 'next_cursor' => '1']]
            : [200, ['next_cursor' => '2', 'events' => $cursor !== '1' ? [] : [
                ['event_type' => 'authorization.role.unassigned', 'occurred_at' => $at, 'organization_id' => 'org_1', 'data' => ['subject_id' => 'usr_dan', 'role_id' => 'rol_1']],
                ['event_type' => 'authorization.role.unassigned', 'occurred_at' => $at, 'organization_id' => 'org_1', 'data' => ['subject_id' => 'svc_batch', 'role_id' => 'rol_1']],
                ['event_type' => 'security.refresh_reuse_detected', 'occurred_at' => $at, 'data' => ['subject_id' => 'usr_erin', 'family_id' => 'rff_1']],
                ['event_type' => 'security.refresh_reuse_detected', 'occurred_at' => $at, 'data' => ['subject_id' => 'svc_batch', 'family_id' => 'rff_2']],
                ['event_type' => 'organization.suspended', 'occurred_at' => $at, 'organization_id' => 'org_9', 'data' => []],
                ['event_type' => 'organization.membership.removed', 'occurred_at' => $at, 'organization_id' => 'org_7', 'data' => ['user_id' => 'usr_fay']],
            ]]]);
        $state = self::state($t, $clock);
        $state->start();
        $state->sync();
        $t0 = self::T0 - 1000;
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_dan', 'ses_d', $t0, 'org_1')));
        $state->check(self::claims('usr_dan', 'ses_d', $t0, 'org_2'));
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_erin', 'ses_e', $t0, '')));
        // A service principal subject is not mistaken for a user.
        $state->check(self::claims('svc_batch', 'ses_s', $t0));
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_any', 'ses_o', $t0, 'org_9')));
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_fay', 'ses_f', $t0, 'org_7')));
        $state->check(self::claims('usr_fay', 'ses_f', $t0, 'org_1'));
        $state->check(self::claims('usr_fay', 'ses_f', self::T0 + 5, 'org_7'));
    }

    public function testKeepsKnownRevocationsWhenStartIsCalledAgain(): void
    {
        $t = self::stream(static function (string $cursor): array {
            if ($cursor === 'now') {
                return [200, ['events' => [], 'next_cursor' => '1.0']];
            }
            if ($cursor === '1.0') {
                return [200, ['next_cursor' => '2.0', 'events' => [self::revoked('ses_1', self::T0), ['event_type' => 'user.suspended', 'occurred_at' => self::iso(self::T0), 'data' => ['user_id' => 'usr_2']]]]];
            }
            return [200, ['events' => [], 'next_cursor' => $cursor]];
        });
        $state = self::state($t, new Clock(self::T0));
        $state->start();
        $state->sync();
        $state->start();
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_9', 'ses_1', self::T0 - 1000)));
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_2', 'ses_9', self::T0 - 1000)));
    }

    public function testRewindsToTheRetainedHistoryOn410AndIsFreshOnlyOnceCaughtUp(): void
    {
        $clock = new Clock(self::T0);
        $midReplayFails = true;
        $full = [];
        for ($i = 0; $i < 500; $i++) {
            $full[] = self::revoked("ses_old_{$i}", self::T0 - 3_600_000);
        }
        $cursors = null;
        $t = self::stream(static function (string $cursor) use (&$midReplayFails, $full): array {
            switch ($cursor) {
                case 'now':
                    return [200, ['events' => [], 'next_cursor' => '5.0']];
                case '5.0':
                    return [200, ['events' => [self::revoked('ses_known', self::T0)], 'next_cursor' => '6.0']];
                case '6.0':
                    return [410, ['code' => 'cursor_expired']];
                case '':
                    return [200, ['events' => $full, 'next_cursor' => 'p1']];
                case 'p1':
                    return $midReplayFails ? [503, []] : [200, ['events' => [self::revoked('ses_gap', self::T0)], 'next_cursor' => '9.0']];
                default:
                    return [200, ['events' => [], 'next_cursor' => $cursor]];
            }
        }, $cursors);
        $state = self::state($t, $clock);
        $state->start();
        $state->sync();
        $e = self::assertThrows(CursorExpiredException::class, static fn () => $state->sync());
        self::assertSame(E::Unavailable, $e->errorCode);
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_1', 'ses_known', self::T0)));
        // The replay applies a full page, then fails: not fresh, it has not caught up.
        $clock->now += 30_000;
        self::assertVerifierError(E::Unavailable, static fn () => $state->sync());
        $clock->now += 40_000;
        self::assertVerifierError(E::StaleState, static fn () => $state->check(self::claims('usr_1', 'ses_other', self::T0)));
        $midReplayFails = false;
        $state->sync();
        foreach (['ses_known', 'ses_gap', 'ses_old_0'] as $sid) {
            self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_1', $sid, self::T0)), $sid);
        }
        $state->check(self::claims('usr_1', 'ses_other', self::T0));
        self::assertSame(['now', '5.0', '6.0', ''], array_slice($cursors, 0, 4));
    }

    public function testRunReportsThe410ReplaysTheRetainedHistoryAndKeepsFollowing(): void
    {
        $expired = 0;
        $t = self::stream(static function (string $cursor) use (&$expired): array {
            switch ($cursor) {
                case 'now':
                    return [200, ['events' => [], 'next_cursor' => '1.0']];
                case '1.0':
                    $expired++;
                    return [410, ['code' => 'cursor_expired']];
                case '':
                    return [200, ['events' => [self::revoked('ses_gap', self::T0)], 'next_cursor' => '2.0']];
                case '2.0':
                    return [200, ['events' => [self::revoked('ses_next', self::T0)], 'next_cursor' => '3.0']];
                default:
                    return [200, ['events' => [], 'next_cursor' => $cursor]];
            }
        });
        $slept = [];
        $state = self::state($t, new Clock(self::T0), ['sleep' => static function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        }]);
        $state->start();
        $errors = [];
        $iterations = 0;
        $state->run(static function () use ($state, &$iterations): bool {
            if (++$iterations > 50) {
                return true; // safety net; the assertions below fail if we got here
            }
            try {
                $state->check(self::claims('usr_1', 'ses_next', self::T0));
            } catch (VerifierException $e) {
                return $e->errorCode === E::Revoked;
            }
            return false;
        }, static function (\Throwable $e) use (&$errors): void {
            $errors[] = $e;
        });
        self::assertTrue($iterations < 50, 'run() recovered from the expired cursor');
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_1', 'ses_gap', self::T0)));
        self::assertSame(1, $expired);
        self::assertCount(1, $errors);
        self::assertInstanceOf(CursorExpiredException::class, $errors[0]);
        self::assertSame([], $slept, 'the replay starts at once, without a backoff');
        $polls = array_values(array_filter($t->requests, static fn (Request $r): bool => str_contains($r->url, 'wait=20')));
        self::assertTrue(count($polls) >= 1, 'run() long-polls');
    }

    public function testNeverWeakensARevocationWhenAnOlderEventIsReplayed(): void
    {
        $t2 = self::T0;
        $t1 = self::T0 - 3_600_000;
        $suspended = static fn (int $at): array => ['event_type' => 'user.suspended', 'occurred_at' => self::iso($at), 'data' => ['user_id' => 'usr_1']];
        $t = self::stream(static function (string $cursor) use ($suspended, $t1, $t2): array {
            if ($cursor === 'now') {
                return [200, ['events' => [], 'next_cursor' => '1.0']];
            }
            if ($cursor === '1.0') {
                return [200, ['events' => [$suspended($t2), $suspended($t1), ['event_type' => 'user.suspended', 'occurred_at' => 'garbage', 'data' => ['user_id' => 'usr_1']]], 'next_cursor' => '2.0']];
            }
            return [200, ['events' => [], 'next_cursor' => $cursor]];
        });
        $state = self::state($t, new Clock(self::T0));
        $state->start();
        $state->sync();
        self::assertVerifierError(E::Revoked, static fn () => $state->check(self::claims('usr_1', 'ses_1', $t2 - 60_000)));
        $state->check(self::claims('usr_1', 'ses_1', $t2 + 1000));
    }

    public function testRunStopsPromptlyDuringABackoff(): void
    {
        $calls = 0;
        $t = new FakeTransport(static function () use (&$calls): Response {
            $calls++;
            throw new TransportException(TransportException::NETWORK, 'down');
        });
        $stop = false;
        $slept = 0;
        $state = self::state($t, new Clock(self::T0), ['sleep' => static function (int $ms) use (&$slept, &$stop): void {
            $slept += $ms;
            if ($slept >= 300) {
                $stop = true;
            }
        }]);
        $errors = 0;
        $state->run(static function () use (&$stop): bool {
            return $stop;
        }, static function () use (&$errors): void {
            $errors++;
        });
        self::assertSame(1, $calls);
        self::assertSame(1, $errors);
        self::assertSame(300, $slept, 'the backoff wait ends once stop is requested');
    }

    public function testBacksOffExponentiallyBetweenFailures(): void
    {
        $calls = 0;
        $t = new FakeTransport(static function () use (&$calls): Response {
            $calls++;
            return FakeTransport::json(503, []);
        });
        $waits = [];
        $lastCalls = 0;
        $state = self::state($t, new Clock(self::T0), ['sleep' => static function (int $ms) use (&$waits, &$calls, &$lastCalls): void {
            if ($calls !== $lastCalls) {
                $waits[] = 0; // a new backoff after another failed poll
                $lastCalls = $calls;
            }
            $waits[count($waits) - 1] += $ms;
        }]);
        $state->run(static function () use (&$calls): bool {
            return $calls >= 7;
        });
        self::assertSame([1000, 2000, 4000, 8000, 16000, 30000], array_slice($waits, 0, 6));
    }

    public function testFailsClosedOnTransportTokenAndResponseErrors(): void
    {
        $clock = new Clock(self::T0);
        foreach ([
            'network' => static fn (): Response => throw new TransportException(TransportException::NETWORK, 'down'),
            'html' => static fn (): Response => new Response(200, [], '<html>'),
            'no cursor' => static fn (): Response => FakeTransport::json(200, ['events' => []]),
            'events object' => static fn (): Response => FakeTransport::json(200, ['events' => ['a' => 1], 'next_cursor' => 'x']),
            '500' => static fn (): Response => FakeTransport::json(500, []),
        ] as $name => $handler) {
            $state = self::state(new FakeTransport($handler), $clock);
            self::assertVerifierError(E::Unavailable, static fn () => $state->start(), (string) $name);
        }
        $ok = new FakeTransport(static fn (): Response => FakeTransport::json(200, ['events' => [], 'next_cursor' => '1']));
        $state = self::state($ok, $clock, ['token' => static fn (): string => throw new \RuntimeException('vault down')]);
        self::assertVerifierError(E::Unavailable, static fn () => $state->start());
        self::assertSame(0, $ok->hits());
        self::assertThrows(\InvalidArgumentException::class, static fn () => self::state($ok, $clock, ['maxStalenessMs' => 0]), static fn (\Throwable $e): bool => $e->getMessage() === 'maxStalenessMs must be positive');
        $state = self::state($ok, $clock, ['realm' => 'main realm/x', 'timeoutMs' => 12_000]);
        $state->start();
        self::assertSame('https://id.test/api/v1/realms/main%20realm%2Fx/session-events?from=now', $ok->last()->url);
        self::assertSame(12_000, $ok->last()->timeoutMs);
        $state->sync(99);
        self::assertStringContains('wait=25', $ok->last()->url);
    }
}

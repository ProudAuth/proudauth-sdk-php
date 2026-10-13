<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\BoundedState;

use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Internal\Time;
use ProudAuth\Sdk\Internal\Url;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Bounded-state verification (SDK-002): the consistency mode between offline
 * JWT verification and per-request introspection. Tokens are verified
 * locally, then checked against revocation state replayed from the identity
 * provider's session-event stream (SES-019). The state is trusted only while
 * it is fresher than `maxStalenessMs`; beyond that every check fails with
 * `stale_state` (HTTP 503). It never silently downgrades to offline
 * acceptance.
 *
 * The state lives in this object, so it suits long-running PHP processes (a
 * worker, RoadRunner, Swoole, ReactPHP or a CLI daemon) that call run() in
 * one place and check() in the request path. Under PHP-FPM, where every
 * request starts empty, prefer the strict-online Introspector.
 */
final class BoundedState
{
    /** Page size requested from the stream (its maximum). */
    private const PAGE_LIMIT = 500;
    /** Pages one sync() call reads at most. */
    private const MAX_PAGES_PER_SYNC = 100;
    private const MAX_RESPONSE_BYTES = 8 << 20;

    private const SUBJECT_EVENTS = [
        // user.recovery_restricted is not a revocation: the server keeps sessions valid.
        'user.suspended', 'user.locked', 'user.deleted', 'user.password_reset',
        'security.refresh_reuse_detected', 'security.credential_compromised',
    ];
    private const ORG_EVENTS = ['organization.suspended', 'organization.deleted', 'organization.archived'];
    private const MEMBER_EVENTS = ['organization.membership.removed', 'organization.membership.suspended', 'authorization.role.unassigned'];
    /**
     * Events naming the assignment's or grant's subject as `subject_id` rather
     * than `user_id`. The subject may also be a service principal (svc_) or a
     * group (grp_); the ID prefix tells them apart, and only users are tracked.
     */
    private const SUBJECT_ID_EVENTS = ['authorization.role.unassigned', 'security.refresh_reuse_detected'];

    private readonly string $endpoint;
    private readonly HttpClient $http;
    /** @var \Closure(): (int|float) */
    private readonly \Closure $now;
    /** @var \Closure(int): void */
    private readonly \Closure $sleep;

    private string $cursor = '';
    private float $synced = 0;
    /** @var array<string, float> */
    private array $sessions = [];
    /** @var array<string, float> */
    private array $subjects = [];
    /** @var array<string, float> */
    private array $orgs = [];
    /** @var array<string, float> */
    private array $members = [];

    /**
     * @param string                         $baseUrl        identity provider origin, e.g. https://id.example.com
     * @param \Closure(): string             $token          service access token (admin audience) carrying
     *                                                       realm.session_events.read; called for every request
     * @param int|float                      $maxStalenessMs how old the replayed state may become before check() fails closed
     * @param int|float                      $timeoutMs      per-request deadline (default 30 000; covers a 25 s long poll)
     * @param (\Closure(): (int|float))|null $now            clock in milliseconds since the epoch (tests)
     * @param (\Closure(int): void)|null     $sleep          sleeps for the given milliseconds (run() backoff; tests)
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        string $baseUrl,
        private readonly string $realm,
        private readonly \Closure $token,
        private readonly int|float $maxStalenessMs,
        private readonly int|float $timeoutMs = 30_000,
        ?Transport $transport = null,
        ?\Closure $now = null,
        ?\Closure $sleep = null,
    ) {
        if (!($maxStalenessMs > 0)) {
            throw new \InvalidArgumentException('maxStalenessMs must be positive');
        }
        $base = Url::requireHttp($baseUrl, 'baseUrl', 'bounded-state');
        $this->endpoint = rtrim($base->toString(), '/') . '/api/v1/realms/' . HttpClient::encodeUriComponent($realm) . '/session-events';
        $this->http = new HttpClient($transport);
        $this->now = $now ?? Time::nowMs(...);
        $this->sleep = $sleep ?? static function (int $ms): void {
            usleep($ms * 1000);
        };
    }

    /**
     * @param array<string, string> $query
     *
     * @return array{events: list<mixed>, next_cursor: string}
     *
     * @throws VerifierException
     */
    private function get(array $query): array
    {
        $url = $this->endpoint . '?' . Query::fromArray($query)->toString();
        try {
            $token = ($this->token)();
            $res = $this->http->send('GET', $url, ['authorization' => 'Bearer ' . $token, 'accept' => 'application/json'], null, (int) ceil($this->timeoutMs), self::MAX_RESPONSE_BYTES);
        } catch (\Exception $cause) {
            throw new VerifierException(VerifierErrorCode::Unavailable, $cause);
        }
        if ($res->status === 410) {
            throw new CursorExpiredException();
        }
        if ($res->status !== 200) {
            throw new VerifierException(VerifierErrorCode::Unavailable);
        }
        $page = json_decode($res->body, true);
        $events = is_array($page) ? ($page['events'] ?? []) : null;
        $next = is_array($page) ? ($page['next_cursor'] ?? null) : null;
        if (!is_array($events) || !array_is_list($events) || !is_string($next)) {
            throw new VerifierException(VerifierErrorCode::Unavailable);
        }
        return ['events' => $events, 'next_cursor' => $next];
    }

    /**
     * Positions the stream at "now"; call before accepting traffic. Calling it
     * again keeps every revocation already replayed: the stream has no
     * snapshot that could supersede them, so a restart only moves the position
     * forward.
     *
     * @throws VerifierException
     */
    public function start(): void
    {
        $page = $this->get(['from' => 'now']);
        $this->cursor = $page['next_cursor'];
        $this->synced = (float) ($this->now)();
    }

    /**
     * Reads all pending events (`$waitSeconds` long-polls, 0 to 25). The state
     * counts as fresh only once a read reaches the end of the stream, so a
     * partly replayed backlog never passes for current state. A 410 rewinds
     * to the beginning of the retained history (keeping the known
     * revocations) and throws CursorExpiredException; the next sync() replays
     * that history, which includes the events after the expired cursor.
     *
     * @throws VerifierException
     */
    public function sync(int|float $waitSeconds = 0): void
    {
        for ($i = 0; $i < self::MAX_PAGES_PER_SYNC; $i++) {
            $cursor = $this->cursor;
            $query = ['cursor' => $cursor, 'limit' => (string) self::PAGE_LIMIT];
            if ($i === 0 && $waitSeconds > 0) {
                $query['wait'] = (string) min(25, (int) floor($waitSeconds));
            }
            try {
                $page = $this->get($query);
            } catch (CursorExpiredException $err) {
                // No snapshot exists, so the full resynchronization is a replay of the
                // retained history ('' is its beginning). $synced is left alone: the
                // state turns stale if the replay does not catch up in time.
                if ($this->cursor === $cursor) {
                    $this->cursor = '';
                }
                throw $err;
            }
            foreach ($page['events'] as $ev) {
                $this->apply($ev);
            }
            $this->cursor = $page['next_cursor'];
            if (count($page['events']) < self::PAGE_LIMIT) {
                $this->synced = (float) ($this->now)();
                return;
            }
        }
    }

    private function apply(mixed $ev): void
    {
        if (!is_array($ev)) {
            return;
        }
        $type = $ev['event_type'] ?? null;
        $type = is_string($type) ? $type : '';
        $at = Time::parseMs($ev['occurred_at'] ?? null);
        $data = $ev['data'] ?? null;
        $str = static fn (string $k): string => is_array($data) && is_string($data[$k] ?? null) ? $data[$k] : '';
        $evOrg = is_string($ev['organization_id'] ?? null) ? $ev['organization_id'] : '';
        $user = $str('user_id');
        if (in_array($type, self::SUBJECT_ID_EVENTS, true)) {
            $user = str_starts_with($str('subject_id'), 'usr_') ? $str('subject_id') : '';
        }
        if ($type === 'session.revoked' && $str('session_id') !== '') {
            self::revokeAt($this->sessions, $str('session_id'), $at);
        } elseif (in_array($type, self::SUBJECT_EVENTS, true) && $user !== '') {
            self::revokeAt($this->subjects, $user, $at);
        } elseif (in_array($type, self::ORG_EVENTS, true)) {
            $org = $str('organization_id') !== '' ? $str('organization_id') : $evOrg;
            if ($org !== '') {
                self::revokeAt($this->orgs, $org, $at);
            }
        } elseif (in_array($type, self::MEMBER_EVENTS, true) && $user !== '' && $evOrg !== '') {
            self::revokeAt($this->members, $user . '|' . $evOrg, $at);
        }
    }

    /**
     * Keeps the latest revocation time for the key, so a replay never weakens the state.
     *
     * @param array<string, float> $m
     */
    private static function revokeAt(array &$m, string $key, float $at): void
    {
        $prev = $m[$key] ?? null;
        if ($prev === null || is_nan($prev) || $at > $prev) {
            $m[$key] = $at;
        }
    }

    /**
     * Throws stale_state when the state is too old, revoked when the claims
     * were revoked.
     *
     * @throws VerifierException
     */
    public function check(Claims $c): void
    {
        if ($this->synced === 0.0 || (float) ($this->now)() - $this->synced > $this->maxStalenessMs) {
            throw new VerifierException(VerifierErrorCode::StaleState);
        }
        $issued = $c->issuedAt !== null ? Time::toMs($c->issuedAt) : 0.0;
        $before = static function (array $m, string $k) use ($issued): bool {
            $at = $m[$k] ?? null;
            return $at !== null && $issued <= $at;
        };
        if ($c->sessionId !== '' && array_key_exists($c->sessionId, $this->sessions)) {
            throw new VerifierException(VerifierErrorCode::Revoked);
        }
        if ($before($this->subjects, $c->subject)) {
            throw new VerifierException(VerifierErrorCode::Revoked);
        }
        if ($c->orgId !== '' && ($before($this->orgs, $c->orgId) || $before($this->members, $c->subject . '|' . $c->orgId))) {
            throw new VerifierException(VerifierErrorCode::Revoked);
        }
    }

    /**
     * Keeps the state current until `$shouldStop` returns true; errors go to
     * `$onError`. Each iteration long-polls with sync(20). After a
     * CursorExpiredException (reported too) it replays the retained history
     * at once instead of waiting, then keeps following the stream. Other
     * errors back off exponentially (1 s up to 30 s); the backoff ends early
     * when `$shouldStop` turns true.
     *
     * @param \Closure(): bool                $shouldStop checked before every poll and during backoff
     * @param (\Closure(\Throwable): void)|null $onError
     */
    public function run(\Closure $shouldStop, ?\Closure $onError = null, int $waitSeconds = 20): void
    {
        $backoff = 1000;
        $resyncing = false;
        while (!$shouldStop()) {
            try {
                $this->sync($waitSeconds);
                $backoff = 1000;
                $resyncing = false;
            } catch (\Exception $err) {
                if ($shouldStop()) {
                    return; // stopping, not failing
                }
                if ($onError !== null) {
                    $onError($err);
                }
                if ($err instanceof CursorExpiredException && !$resyncing) {
                    // sync() rewound to the retained history: replay it now. A second
                    // 410 in a row waits like any other error.
                    $resyncing = true;
                    continue;
                }
                for ($slept = 0; $slept < $backoff && !$shouldStop(); $slept += 100) {
                    ($this->sleep)(min(100, $backoff - $slept));
                }
                $backoff = min($backoff * 2, 30_000);
            }
        }
    }
}

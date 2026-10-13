<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

use ProudAuth\Sdk\Http\Transport;
use ProudAuth\Sdk\Http\TransportException;
use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Internal\Url;
use ProudAuth\Sdk\Version;

/**
 * Typed client for the ProudAuth administration and self-service APIs
 * (SDK-003, SDK-007), a port of the Node SDK's admin module and the Go SDK's
 * admin package. It preserves RFC 9457 problem details, iterates
 * opaque-cursor pages, enforces deadlines, sends idempotency keys and
 * If-Match preconditions, sends its version, reports deprecated operations,
 * wraps one-time secrets in Secret, and never logs request bodies or tokens
 * (SDK-008).
 *
 * Calls one realm's custom APIs under /api/v1/realms/{realm}.
 */
final class AdminClient
{
    /** This SDK's version, sent with every request. */
    public const SDK_VERSION = Version::SDK_VERSION;

    /** Response members that carry one-time secrets (the server's list for its idempotency store). */
    public const SECRET_MEMBERS = [
        'client_secret', 'client_secrets', 'api_key', 'signing_secret', 'setup_token', 'recovery_codes', 'invitation_secret',
        'access_token', 'refresh_token', 'id_token', 'handoff_code', 'download_token', 'token', 'secret', 'webhook_secrets',
    ];

    private const USER_STATE_ACTIONS = ['suspend', 'reactivate', 'lock'];

    private readonly string $base;
    private readonly HttpClient $http;

    /**
     * @param string                                                 $baseUrl          e.g. https://id.example.com
     * @param string|(\Closure(): string)|null                       $token            bearer token, or a source called once per request
     * @param int|float                                              $timeoutMs        default request deadline (default 30 000)
     * @param string|null                                            $userAgent        sent before "proudauth-sdk-php/0.2.0"
     * @param int                                                    $maxResponseBytes maximum response size (default 32 MiB)
     * @param (\Closure(string, string, string, ?string): void)|null $onDeprecated     called as ($method, $path, $deprecation,
     *                                                                                 $sunset) for responses of operations the server
     *                                                                                 marks deprecated (API-013); the path has no query
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        string $baseUrl,
        string $realm,
        private readonly string|\Closure|null $token = null,
        private readonly int|float $timeoutMs = 30_000,
        private readonly ?string $userAgent = null,
        ?Transport $transport = null,
        private readonly int $maxResponseBytes = 32 << 20,
        private readonly ?\Closure $onDeprecated = null,
    ) {
        if ($realm === '') {
            throw new \InvalidArgumentException('admin: realm is required');
        }
        $base = Url::requireHttp($baseUrl, 'baseUrl', 'admin');
        $this->base = rtrim($base->toString(), '/') . '/api/v1/realms/' . HttpClient::encodeUriComponent($realm);
        $this->http = new HttpClient($transport);
    }

    /** A random idempotency key (32 hex characters). */
    public static function newIdempotencyKey(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Performs a request against /api/v1/realms/{realm}{path} and decodes JSON.
     * A $body of null sends no body; an empty PHP array is sent as {}.
     *
     * @throws ProblemException      for HTTP errors (status >= 400)
     * @throws AdminRequestException for transport failures, timeouts and invalid responses
     * @throws \InvalidArgumentException for an invalid path or a body that cannot be encoded
     */
    public function request(string $method, string $path, mixed $body = null, ?RequestOptions $options = null): AdminResponse
    {
        if (!str_starts_with($path, '/')) {
            throw new \InvalidArgumentException('admin: path must start with "/"');
        }
        $options ??= new RequestOptions();
        $shownPath = self::stripQuery($path);
        $headers = ['accept' => 'application/json, application/problem+json'];
        $payload = null;
        if ($body !== null) {
            $headers['content-type'] = 'application/json';
            try {
                $payload = $body === [] ? '{}' : json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
            } catch (\JsonException) {
                throw new \InvalidArgumentException('admin: request body is not JSON-encodable');
            }
        }
        $headers['proudauth-sdk'] = 'php/' . self::SDK_VERSION;
        $headers['user-agent'] = ($this->userAgent !== null && $this->userAgent !== '' ? $this->userAgent . ' ' : '') . 'proudauth-sdk-php/' . self::SDK_VERSION;
        if ($this->token !== null) {
            try {
                $tok = is_string($this->token) ? $this->token : ($this->token)();
                if (!is_string($tok)) {
                    throw new \UnexpectedValueException('token source returned no string');
                }
            } catch (\Throwable $cause) {
                throw new AdminRequestException(AdminErrorCode::TokenSource, $method, $shownPath, $cause);
            }
            $headers['authorization'] = 'Bearer ' . $tok;
        }
        if ($options->idempotencyKey !== null && $options->idempotencyKey !== '') {
            $headers['idempotency-key'] = $options->idempotencyKey;
        }
        if ($options->ifMatch !== null && $options->ifMatch !== '') {
            $headers['if-match'] = $options->ifMatch;
        }
        $timeout = (int) ceil($options->timeoutMs ?? $this->timeoutMs);
        try {
            $res = $this->http->send($method, $this->base . $path, $headers, $payload, max(1, $timeout), $this->maxResponseBytes);
        } catch (TransportException $cause) {
            $code = $cause->kind === TransportException::TIMEOUT ? AdminErrorCode::Timeout : AdminErrorCode::Network;
            throw new AdminRequestException($code, $method, $shownPath, $cause);
        } catch (\Exception $cause) {
            throw new AdminRequestException(AdminErrorCode::Network, $method, $shownPath, $cause);
        }
        $parsed = null;
        if ($res->body !== '') {
            try {
                $parsed = json_decode($res->body, true, 512, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
            } catch (\JsonException $cause) {
                if ($res->status < 400) {
                    throw new AdminRequestException(AdminErrorCode::InvalidResponse, $method, $shownPath, $cause);
                }
                $parsed = null;
            }
        }
        $deprecation = $res->header('deprecation');
        $sunset = $res->header('sunset');
        if ($deprecation !== null && $deprecation !== '' && $this->onDeprecated !== null) {
            ($this->onDeprecated)($method, $shownPath, $deprecation, $sunset);
        }
        if ($res->status >= 400) {
            $problem = is_array($parsed) && ($parsed === [] || !array_is_list($parsed)) ? $parsed : [];
            throw new ProblemException($res->status, $problem, $res->headers);
        }
        return new AdminResponse($res->status, $res->headers, $res->header('etag'), $deprecation, $sunset, self::wrapSecrets($parsed));
    }

    /**
     * Iterates the pages of a cursor-paginated list endpoint (API-004).
     *
     * @return \Generator<int, Page>
     *
     * @throws ProblemException
     * @throws AdminRequestException invalid_response when the server repeats a cursor
     */
    public function pages(string $path, ?RequestOptions $options = null): \Generator
    {
        $cursor = '';
        $seen = [];
        for (;;) {
            $p = $path;
            if ($cursor !== '') {
                $p .= (str_contains($p, '?') ? '&' : '?') . 'cursor=' . HttpClient::encodeUriComponent($cursor);
            }
            $data = $this->request('GET', $p, null, $options)->data;
            $items = is_array($data) && isset($data['items']) && is_array($data['items']) ? array_values($data['items']) : [];
            $next = is_array($data) && isset($data['next_cursor']) && is_string($data['next_cursor']) ? $data['next_cursor'] : '';
            yield new Page($items, $next);
            if ($next === '') {
                return;
            }
            if (isset($seen[$next])) {
                throw new AdminRequestException(AdminErrorCode::InvalidResponse, 'GET', self::stripQuery($path)); // cursor loop
            }
            $seen[$next] = true;
            $cursor = $next;
        }
    }

    /**
     * Iterates every item of a cursor-paginated list endpoint.
     *
     * @return \Generator<int, mixed>
     */
    public function list(string $path, ?RequestOptions $options = null): \Generator
    {
        foreach ($this->pages($path, $options) as $page) {
            yield from $page->items;
        }
    }

    /** @return \Generator<int, array<string, mixed>> users */
    public function users(string $query = '', ?RequestOptions $options = null): \Generator
    {
        return $this->list('/users?q=' . HttpClient::encodeUriComponent($query), $options);
    }

    /** Reads a user with its ETag. */
    public function getUser(string $userId, ?RequestOptions $options = null): AdminResponse
    {
        return $this->request('GET', '/users/' . self::seg($userId), null, $options);
    }

    /**
     * Creates a user. A random idempotency key is used unless one is given
     * (reuse it when retrying).
     *
     * @param array<string, mixed> $input
     *
     * @return array<string, mixed>
     */
    public function createUser(array $input, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/users', $input, self::idempotent($options))->data);
    }

    /**
     * Updates a user; pass the ETag from getUser() as ifMatch to reject stale writes.
     *
     * @param array<string, mixed> $patch
     */
    public function updateUser(string $userId, array $patch, ?RequestOptions $options = null): AdminResponse
    {
        return $this->request('PATCH', '/users/' . self::seg($userId), $patch, $options);
    }

    /**
     * Suspends, reactivates or locks a user.
     *
     * @param string $action "suspend", "reactivate" or "lock"
     */
    public function setUserState(string $userId, string $action, string $reason, ?RequestOptions $options = null): void
    {
        if (!in_array($action, self::USER_STATE_ACTIONS, true)) {
            throw new \InvalidArgumentException('admin: unknown user state action');
        }
        $this->request('POST', '/users/' . self::seg($userId) . '/' . $action, ['reason' => $reason], $options);
    }

    /** Revokes all sessions of a user; returns the number revoked. */
    public function revokeSessions(string $userId, ?RequestOptions $options = null): int
    {
        $data = $this->request('POST', '/users/' . self::seg($userId) . '/revoke-sessions', new \stdClass(), $options)->data;
        return is_array($data) && isset($data['revoked_sessions']) && is_int($data['revoked_sessions']) ? $data['revoked_sessions'] : 0;
    }

    /** @return \Generator<int, array<string, mixed>> organizations */
    public function organizations(?RequestOptions $options = null): \Generator
    {
        return $this->list('/organizations', $options);
    }

    /** @return array<string, mixed> the organization */
    public function createOrganization(string $slug, string $displayName, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/organizations', ['slug' => $slug, 'display_name' => $displayName], self::idempotent($options))->data);
    }

    /** @return \Generator<int, array<string, mixed>> memberships */
    public function members(string $orgId, ?RequestOptions $options = null): \Generator
    {
        return $this->list('/organizations/' . self::seg($orgId) . '/members', $options);
    }

    /**
     * Adds an existing user to an organization.
     *
     * @param list<string> $roleIds
     *
     * @return array<string, mixed> the membership
     */
    public function addMember(string $orgId, string $userId, array $roleIds, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/organizations/' . self::seg($orgId) . '/members', ['user_id' => $userId, 'role_ids' => array_values($roleIds)], $options)->data);
    }

    /**
     * Creates an invitation.
     *
     * @param list<string> $roleIds
     *
     * @return array<string, mixed>
     */
    public function invite(string $orgId, string $email, array $roleIds, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/organizations/' . self::seg($orgId) . '/invitations', ['email' => $email, 'role_ids' => array_values($roleIds)], self::idempotent($options))->data);
    }

    /** @return list<array<string, mixed>> roles for a boundary type */
    public function roles(string $boundary, ?RequestOptions $options = null): array
    {
        return self::items($this->request('GET', '/roles?boundary_type=' . HttpClient::encodeUriComponent($boundary), null, $options)->data);
    }

    /**
     * Assigns a role to a subject within a scope.
     *
     * @param array{type: string, id: string} $subject
     * @param array{type: string, id: string} $scope
     *
     * @return array<string, mixed>
     */
    public function assign(string $roleId, array $subject, array $scope, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/role-assignments', ['role_id' => $roleId, 'subject' => $subject, 'scope' => $scope], $options)->data);
    }

    /**
     * Registers an OAuth client; the secret is returned once (as a Secret).
     *
     * @param array<string, mixed> $input
     *
     * @return array<string, mixed>
     */
    public function createClient(array $input, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/clients', $input, $options)->data);
    }

    /**
     * Issues an overlapping client secret.
     *
     * @return array<string, mixed>
     */
    public function rotateClientSecret(string $clientRef, int $retireOthersAfterSec, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/clients/' . self::seg($clientRef) . '/credentials', ['retire_others_after_seconds' => $retireOthersAfterSec], $options)->data);
    }

    /**
     * Requests support access (requires recent MFA and a reason).
     *
     * @param array<string, mixed> $input
     *
     * @return array<string, mixed>
     */
    public function requestImpersonation(array $input, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/impersonation-requests', $input, $options)->data);
    }

    /** @return array<string, mixed> the issued support grant */
    public function issueImpersonation(string $requestId, ?RequestOptions $options = null): array
    {
        return self::object($this->request('POST', '/impersonation-requests/' . self::seg($requestId) . '/issue', null, $options)->data);
    }

    /** Ends a support grant. */
    public function revokeImpersonation(string $grantId, string $reason, ?RequestOptions $options = null): void
    {
        $this->request('POST', '/impersonation-grants/' . self::seg($grantId) . '/revoke', ['reason' => $reason], $options);
    }

    /** @return \Generator<int, array<string, mixed>> OAuth clients */
    public function clients(?RequestOptions $options = null): \Generator
    {
        return $this->list('/clients', $options);
    }

    /**
     * Sets the scopes and subject types a client may request for a resource.
     *
     * @param list<string> $scopes
     * @param list<string> $subjectTypes
     */
    public function setResourceGrant(string $clientRef, string $resourceId, array $scopes, array $subjectTypes, ?RequestOptions $options = null): void
    {
        $this->request('PUT', '/clients/' . self::seg($clientRef) . '/resource-grants/' . self::seg($resourceId), ['allowed_scopes' => array_values($scopes), 'subject_types' => array_values($subjectTypes)], $options);
    }

    /** @return list<array<string, mixed>> a user's active sessions */
    public function userSessions(string $userId, ?RequestOptions $options = null): array
    {
        return self::items($this->request('GET', '/users/' . self::seg($userId) . '/sessions', null, $options)->data);
    }

    /** Revokes one session of a user (SES-003). */
    public function revokeSession(string $userId, string $sessionId, ?RequestOptions $options = null): void
    {
        $this->request('DELETE', '/users/' . self::seg($userId) . '/sessions/' . self::seg($sessionId), null, $options);
    }

    /** @return \Generator<int, array<string, mixed>> an organization's invitations, optionally by state */
    public function invitations(string $orgId, string $state = '', ?RequestOptions $options = null): \Generator
    {
        return $this->list('/organizations/' . self::seg($orgId) . '/invitations?state=' . HttpClient::encodeUriComponent($state), $options);
    }

    /** Revokes a pending invitation. */
    public function revokeInvitation(string $orgId, string $invitationId, ?RequestOptions $options = null): void
    {
        $this->request('POST', '/organizations/' . self::seg($orgId) . '/invitations/' . self::seg($invitationId) . '/revoke', null, $options);
    }

    /**
     * Creates up to 100 invitations with per-item results (INV-011).
     *
     * @param list<array<string, mixed>> $items
     *
     * @return list<array<string, mixed>>
     */
    public function inviteBatch(string $orgId, array $items, ?RequestOptions $options = null): array
    {
        $data = $this->request('POST', '/organizations/' . self::seg($orgId) . '/invitations/batch', ['items' => array_values($items)], self::idempotent($options))->data;
        return is_array($data) && isset($data['results']) && is_array($data['results']) ? array_values($data['results']) : [];
    }

    /**
     * Lists support grants (filters: actor_user_id, target_user_id, organization_id, state).
     *
     * @param array<string, string> $filter
     *
     * @return list<array<string, mixed>>
     */
    public function impersonationGrants(array $filter = [], ?RequestOptions $options = null): array
    {
        return self::items($this->request('GET', '/impersonation-grants?' . Query::fromArray($filter)->toString(), null, $options)->data);
    }

    /**
     * Explains a subject's effective permissions with provenance (AZ-009).
     *
     * @return array<string, mixed>
     */
    public function subjectPermissions(string $subjectId, string $orgId = '', ?RequestOptions $options = null): array
    {
        $q = $orgId !== '' ? '?organization_id=' . HttpClient::encodeUriComponent($orgId) : '';
        return self::object($this->request('GET', '/subjects/' . self::seg($subjectId) . '/permissions' . $q, null, $options)->data);
    }

    /**
     * Queries audit evidence.
     *
     * @param array<string, string> $filter
     *
     * @return \Generator<int, array<string, mixed>>
     */
    public function auditEvents(array $filter = [], ?RequestOptions $options = null): \Generator
    {
        return $this->list('/audit-events?' . Query::fromArray($filter)->toString(), $options);
    }

    /** Hides the token from var_dump() and print_r(). */
    public function __debugInfo(): array
    {
        return ['base' => $this->base, 'token' => $this->token === null ? null : '[REDACTED]'];
    }

    private static function idempotent(?RequestOptions $options): RequestOptions
    {
        // An explicit null key must not clobber the generated one.
        return ($options ?? new RequestOptions())->withDefaultIdempotencyKey(self::newIdempotencyKey());
    }

    private static function seg(string $v): string
    {
        if ($v === '') {
            throw new \InvalidArgumentException('admin: path identifiers must be non-empty strings');
        }
        return HttpClient::encodeUriComponent($v);
    }

    private static function stripQuery(string $path): string
    {
        $q = strpos($path, '?');
        return $q === false ? $path : substr($path, 0, $q);
    }

    /** @return array<string, mixed> */
    private static function object(mixed $data): array
    {
        return is_array($data) ? $data : [];
    }

    /** @return list<array<string, mixed>> */
    private static function items(mixed $data): array
    {
        return is_array($data) && isset($data['items']) && is_array($data['items']) ? array_values($data['items']) : [];
    }

    private static function seal(mixed $v): mixed
    {
        if (is_string($v)) {
            return new Secret($v);
        }
        if (is_array($v)) {
            return array_map(self::seal(...), $v);
        }
        return $v;
    }

    /** Replaces secret-bearing values in a decoded response with Secret, recursively. */
    private static function wrapSecrets(mixed $v): mixed
    {
        if (!is_array($v)) {
            return $v;
        }
        $out = [];
        foreach ($v as $k => $x) {
            $out[$k] = is_string($k) && in_array($k, self::SECRET_MEMBERS, true) ? self::seal($x) : self::wrapSecrets($x);
        }
        return $out;
    }
}

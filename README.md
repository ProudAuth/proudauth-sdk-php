<p align="center">
  <a href="https://proudauth.com"><img src="https://raw.githubusercontent.com/ProudAuth/.github/main/assets/banner-proudauth-sdk-php.png" alt="ProudAuth SDK for PHP" width="100%"></a>
</p>

<p align="center">
  <a href="https://github.com/ProudAuth/proudauth-sdk-php"><img alt="PHP" src="https://img.shields.io/badge/PHP-SDK-3ee6b0?logo=php&logoColor=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://github.com/ProudAuth/proudauth-sdk-php/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ProudAuth/proudauth-sdk-php/ci.yml?branch=main&label=ci&style=for-the-badge&labelColor=06120e"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
  <a href="https://proudauth.com/docs/sdks/php/"><img alt="Documentation" src="https://img.shields.io/badge/docs-proudauth.com-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
</p>

# proudauth/sdk for PHP

> **Repository status:** public standalone source; package version 0.2.0 remains unpublished.
> No package-registry release or stable-support window is promised yet.
> [Documentation](https://proudauth.com/docs/) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

The first-party PHP SDK for ProudAuth (spec §28, SDK-001 to SDK-009). It is a
port of the Node.js SDK in `sdk/node` (and through it of the Go SDK in
`sdk/go`), with the same security behavior:

| Namespace                              | Purpose                                                                                       | Node.js equivalent                | Go equivalent                     |
| -------------------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------- |
| `ProudAuth\Sdk\Verifier`               | Offline JWT access-token verification, `Claims`, `MultiIssuerVerifier`, the error categories  | `@proudauth/sdk/verifier`         | `sdk/go/verifier` (verifier.go, multi.go) |
| `ProudAuth\Sdk\Middleware`             | Framework-neutral request authentication: bearer extraction, RFC 6750 challenges, a `protect()` helper for plain PHP | the adapters in `middleware.ts` | `verifier.Middleware`, `AuthenticateMetadata` |
| `ProudAuth\Sdk\Introspection`          | Strict-online introspection and the support-access contract (`SupportGuard`)                  | `@proudauth/sdk/introspection`    | `sdk/go/verifier` (introspect.go) |
| `ProudAuth\Sdk\BoundedState`           | Local verification plus revocations replayed from the session-event stream, failing closed when stale | `@proudauth/sdk/bounded-state` | `sdk/go/verifier` (boundedstate.go) |
| `ProudAuth\Sdk\Oidc`                   | Backend-for-frontend login: code + PKCE, ID-token validation, refresh, logout                 | `@proudauth/sdk/oidc-client`      | `sdk/go/oidcclient`               |
| `ProudAuth\Sdk\Admin`                  | Typed admin API client: RFC 9457 problems, cursor pagination, idempotency, If-Match, deadlines, one-time secrets wrapped in `Secret`, deprecation reporting | `@proudauth/sdk/admin` | `sdk/go/admin` |
| `ProudAuth\Sdk\Http`, `ProudAuth\Sdk\Cache` | The injectable HTTP transport (`CurlTransport` by default) and the optional key-set store | `fetch` option | `http.Client` |

Version 0.2.0 (`ProudAuth\Sdk\Version::SDK_VERSION`), unpublished. Its
compatibility and security-update policy are the same as the other SDKs'
([docs/integrations/sdk-compatibility.md](https://proudauth.com/docs/integrations/sdk-compatibility/)).

- **No Composer dependencies.** The SDK needs only PHP and the extensions
  `openssl`, `sodium`, `json` and `curl`. It does not depend on PSR packages
  or any framework.
- **PHP 8.2 or later** (see [Supported versions](#supported-versions)).
- **Algorithms:** RS256, PS256, ES256 and EdDSA (Ed25519). The SDK never
  accepts `none` or HMAC, and it only verifies: it contains no signing code.
- License: Apache-2.0.
- Namespace `ProudAuth\Sdk\`, PSR-4 from `src/`. Classes under
  `ProudAuth\Sdk\Internal` and members marked `@internal` are not part of the
  public API.

## Sender-constrained tokens

Token-only verification and introspection reject any `cnf` claim with
`VerifierErrorCode::SenderConstraint`, including malformed or unsupported
bindings. This SDK does not yet provide request-level DPoP or TLS certificate
verification. Use the Go `SenderVerifier` or a separately reviewed request
verifier for bound tokens; see the
[resource-server profile](https://proudauth.com/docs/integrations/resource-servers/#sender-constrained-tokens).

## Installation

The package is not on Packagist yet. Install it from a checkout of this
repository with a Composer path repository:

```json
{
    "repositories": [
        { "type": "path", "url": "../proudauth-sdk-php", "options": { "symlink": false } }
    ],
    "require": {
        "proudauth/sdk": "0.2.0"
    }
}
```

```sh
composer update proudauth/sdk
```

This standalone repository has `composer.json` at its root. You can install
from this public GitHub repository without a subtree split:

```json
{
    "repositories": [{ "type": "vcs", "url": "https://github.com/proudauth/proudauth-sdk-php.git" }],
    "require": { "proudauth/sdk": "dev-main" }
}
```

There is no SDK release tag yet. Composer infers VCS versions from branch/tag
names, so this source installation explicitly selects `dev-main`, not `0.2.0`.
Commit `composer.lock` in your application to retain the exact resolved source
revision. The path-repository example can use the package's declared `0.2.0`.

Without Composer, register a PSR-4 autoloader for `ProudAuth\Sdk\` pointing at
`src/` (the tests do exactly that in `tests/bootstrap.php`).

## Which validation profile should I use?

Every API must decide, per operation, how fresh its view of revocation has to
be (§13.2, §28.2). Write the decision down for each route.

| Profile | Use it for | Revocation exposure |
| --- | --- | --- |
| **Offline JWT** (`Verifier`) | Ordinary, low-risk reads and writes on short-lived JWT access tokens. No per-request network call once the key set is cached. | **Bounded by token lifetime.** A token issued before logout, session revocation, suspension or membership removal keeps working until its `exp` plus the clock skew: with the default 5-minute access tokens and 30 s skew, up to about 5.5 minutes (SES-023, TEST-034). |
| **Strict-online** (`Introspector`) | Identity administration, credential and security changes, payments and other high-risk operations, and any route that must stop at the moment of revocation. | None for new requests. Every request asks the identity provider. If the provider can't be reached, the request is **denied** (503). The SDK never falls back to offline checks and never caches a positive result (TEST-035). |
| **Support** (`SupportGuard`) | Any route that serves administrator support (impersonation) sessions. These sessions carry opaque `pa_it_…` tokens. | Strict-online, plus the support contract: the actor is preserved, the default is read-only, writes need an explicit allowlist, protected operations are always denied, and an audit record is written **before** access (IMP-006 to IMP-020). |
| **Bounded state** (`BoundedState` + `BoundedVerifier`) | Long-running PHP processes (workers, RoadRunner, Swoole, ReactPHP) that verify JWTs locally but must stop accepting them within a known time after revocation. Needs a service token with `realm.session_events.read`. | At most `maxStalenessMs`. When the replayed state is older than that, every check fails closed (503). Under PHP-FPM, where every request starts empty, use the `Introspector` instead. |

Rules that hold in every profile:

- **Support tokens are always strict-online.** The offline `Verifier` rejects
  `impersonation_access`, and it refuses to be configured to accept it.
- **One audience per API.** Configure the exact issuer and this API's own
  audience, never a wildcard.
- **Organization and ownership come from your data.** Compare `$claims->orgId`
  with the organization of the resource as stored in your database
  (`$claims->requireOrganization($row['org_id'])`), never with an ID taken
  from the request.
- **`authz_version` is only a hint.** It means something only when compared
  with trusted current state.

## API with offline verification

Plain PHP (one script per route, or a front controller):

```php
use ProudAuth\Sdk\Cache\FileStore;
use ProudAuth\Sdk\Middleware\RequestAuthenticator;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\Verifier;

$verifier = new Verifier(
    issuer: 'https://id.example.com/realms/main',   // exact; other issuers are rejected before any fetch
    audience: 'https://api.example.com/orders',     // this API only
    // jwksUrl defaults to "{issuer}/jwks"; it is never taken from a token (no jku/x5u)
    cache: new FileStore('/var/cache/orders-api'),  // share the key set across PHP-FPM requests
);

$auth = new RequestAuthenticator($verifier, realm: 'orders', onError: function (Throwable $e): void {
    metrics_increment('auth_failure', ['code' => $e instanceof ProudAuth\Sdk\Verifier\VerifierException ? $e->errorCode->value : 'other']);
});

// Reads $_SERVER (Authorization header, REQUEST_URI). Without verified claims the
// RFC 6750 response is sent and the handler never runs.
$auth->protect(function (Claims $claims): void {
    $claims->requireScope('orders:read');                 // 403 insufficient_scope, scope="orders:read"
    $order = find_order((int) $_GET['id']);
    if ($order === null) {
        http_response_code(404);
        return;
    }
    $claims->requireOrganization($order['org_id']);       // 403 on another tenant's order
    header('Content-Type: application/json');
    echo json_encode($order);
});
```

Anywhere you already have the header value (a framework request, a queue
message, a WebSocket upgrade), authenticate it directly:

```php
use ProudAuth\Sdk\Middleware\Challenge;
use ProudAuth\Sdk\Verifier\VerifierException;

try {
    $claims = $auth->authenticate($request->getHeaderLine('Authorization'), $request->getRequestTarget());
} catch (VerifierException $e) {
    $challenge = Challenge::fromThrowable($e, realm: 'orders');
    // $challenge->status, $challenge->responseHeaders(), $challenge->body()
}
```

`authenticate()` also takes the list of Authorization header values (more than
one is refused), and refuses a request whose query string carries
`access_token` (TOK-023). `ProudAuth\Sdk\Middleware\BearerToken::fromHeader()`
and `::fromGlobals()` extract the token alone.

### PSR-15

The SDK has no PSR dependency, but a PSR-15 middleware around it is a few
lines (with any PSR-17 response factory):

```php
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ProudAuth\Sdk\Middleware\RequestAuthenticator;

final class ProudAuthMiddleware implements MiddlewareInterface
{
    public function __construct(private RequestAuthenticator $auth, private ResponseFactoryInterface $responses) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $claims = $this->auth->authenticate($request->getHeader('Authorization'), $request->getRequestTarget());
        } catch (Throwable $e) {
            $c = $this->auth->challenge($e);
            $response = $this->responses->createResponse($c->status);
            foreach ($c->responseHeaders() as $name => $value) {
                $response = $response->withHeader($name, $value);
            }
            $response->getBody()->write($c->body());
            return $response;
        }
        return $handler->handle($request->withAttribute('proudauth.claims', $claims));
    }
}
```

Handlers then read `$request->getAttribute('proudauth.claims')`, and turn a
`VerifierException` thrown by `requireScope()` or `requireOrganization()` into
`$auth->challenge($e)` (403) in your error handler.

### Key-set caching across requests

PHP-FPM builds every object afresh for each request, so a `Verifier` on its
own would fetch the JWKS once per request. Pass a `ProudAuth\Sdk\Cache\Store`
as `cache` to keep the key set and its refresh bookkeeping across requests and
workers: `FileStore` (a private directory, files written atomically with mode
0600), `MemoryStore` (one process), or your own two-method adapter (APCu,
Redis). With a store, the unknown-`kid` refresh bound (`minRefreshIntervalMs`)
holds for the whole application instead of per request. Anyone who can write
to the store can make the verifier trust a key, so use storage only the
application can write.

### Several issuers

An application that accepts tokens from several realms registers each issuer
with its own tenant (INT-009). A token from any other issuer is rejected with
the `issuer` category, even when it is validly signed. Key your records by
tenant and subject, never by email:

```php
use ProudAuth\Sdk\Verifier\IssuerRegistration;
use ProudAuth\Sdk\Verifier\MultiIssuerVerifier;
use ProudAuth\Sdk\Verifier\Verifier;

$multi = new MultiIssuerVerifier([
    'https://id.example.com/realms/acme'   => new IssuerRegistration(new Verifier(issuer: 'https://id.example.com/realms/acme', audience: $audience), 'acme'),
    'https://id.example.com/realms/globex' => new IssuerRegistration(new Verifier(issuer: 'https://id.example.com/realms/globex', audience: $audience), 'globex'),
]);
$result = $multi->verifyTenant($rawToken);   // $result->claims, $result->tenant
```

`MultiIssuerVerifier` is also an `Authenticator`, so it works with
`RequestAuthenticator`, but then the tenant is not passed on.

### Responses

`RequestAuthenticator` and `Challenge` answer according to RFC 6750, like the
Node and Go adapters:

| Outcome | Status | `WWW-Authenticate` |
| --- | --- | --- |
| No bearer token | 401 | `Bearer` (with `realm="…"` when configured) |
| `access_token` in the query string (TOK-023) | 400 | `Bearer error="invalid_request"` |
| Invalid, expired or wrong-audience token, ID token, unknown key, inactive, revoked | 401 | `Bearer error="invalid_token"` |
| Missing scope | 403 | `Bearer error="insufficient_scope", scope="…"` |
| Organization mismatch | 403 | `Bearer error="insufficient_scope"` |
| Support-policy denial | 403 | none |
| JWKS, introspection, audit store or event stream unavailable, stale bounded state | 503 | none (fails closed) |
| Misconfiguration (`contract`), or any error that is not a `VerifierException` | 500 | none |

Every failure response carries `Cache-Control: no-store` and a short
plain-text body without token material. CORS preflights carry no
`Authorization` header: answer them before authenticating.

You can verify a token directly with `$verifier->verify($rawToken)`. It
returns an immutable `Claims` (`subject`, `audience`, `clientId`, `scopes`,
`orgId`, `sessionId`, `tokenKind`, `jti`, `actor`, `issuedAt`, `expiry`,
`authTime`, `acr`, `authzVersion`, …) or throws a `VerifierException`.

## Errors

| Exception | Category (`$e->errorCode`) | Thrown by |
| --- | --- | --- |
| `ProudAuth\Sdk\Verifier\VerifierException` | `VerifierErrorCode` enum: `missing_token`, `invalid_request`, `malformed`, `too_large`, `duplicate_claim`, `token_type`, `algorithm`, `unknown_key`, `signature`, `issuer`, `audience`, `expired`, `not_yet_valid`, `future_issued`, `token_kind`, `inactive`, `unavailable`, `organization`, `scope`, `support_policy`, `contract`, `stale_state`, `revoked` (the Node SDK's `VERIFIER_ERROR_CODES`) | verifier, introspection, support guard, bounded state, claims helpers, request helpers |
| `ProudAuth\Sdk\BoundedState\CursorExpiredException` | `unavailable` (extends `VerifierException`) | `BoundedState::sync()` on `410 cursor_expired` |
| `ProudAuth\Sdk\Oidc\OidcException` | `OidcErrorCode` enum: `state`, `id_token`, `nonce`, `reauthenticate`, `provider`, `configuration`; plus `reason`, `providerError`, `status` | `OidcClient`, `Session` |
| `ProudAuth\Sdk\Admin\ProblemException` | the problem's `code` (string); `status`, `title`, `detail`, `type`, `instance`, `errors`, `requestId`, `extra`, `headers` | `AdminClient` for HTTP errors |
| `ProudAuth\Sdk\Admin\AdminRequestException` | `AdminErrorCode` enum: `timeout`, `network`, `invalid_response`, `token_source` | `AdminClient` for transport failures |
| `InvalidArgumentException` | — | constructors and helpers, for invalid configuration or arguments |

Messages carry categories only ("verifier: wrong audience",
"oidc-client: invalid ID token (at_hash)") and never contain tokens, secrets,
request bodies or claim values (SDK-008). The cause, when there is one, is
`getPrevious()`. Use the category, never the message, in telemetry.

## Strict-online, support-aware API

```php
use ProudAuth\Sdk\Introspection\Introspector;
use ProudAuth\Sdk\Introspection\SupportEvent;
use ProudAuth\Sdk\Introspection\SupportGuard;
use ProudAuth\Sdk\Middleware\RequestAuthenticator;
use ProudAuth\Sdk\Verifier\Claims;

$introspector = new Introspector(
    endpoint: 'https://id.example.com/realms/main/oauth/introspect',
    clientId: getenv('ORDERS_RS_CLIENT_ID'),          // a confidential client registered as this resource server
    clientSecret: getenv('ORDERS_RS_CLIENT_SECRET'),  // sent with client_secret_basic, never logged
    issuer: 'https://id.example.com/realms/main',
    audience: 'https://api.example.com/orders',
    timeoutMs: 3000,                                  // a timeout denies the request, it doesn't downgrade
);

$guard = new SupportGuard(
    introspector: $introspector,
    // Called BEFORE access for every support request, allowed or denied. If it throws, access is denied (503).
    auditor: function (SupportEvent $ev) use ($db): void {
        $db->insert('support_audit', [
            'grant_id' => $ev->grantId, 'actor' => $ev->actor, 'subject' => $ev->subject, 'org_id' => $ev->orgId,
            'operation' => $ev->operation, 'allowed' => $ev->allowed, 'deny_reason' => $ev->denyReason,
            'at' => $ev->at->format(DATE_ATOM),
        ]);
    },
    writeOperations: ['orders.annotate'], // the only writes allowed, and only for allowlisted_write grants
);

// One introspection per request. Ordinary tokens follow the introspector's accepted kinds;
// support tokens follow the support contract. Routing uses the authoritative token_kind, never a token prefix.
(new RequestAuthenticator($guard->route('orders.list', read: true)))->protect(function (Claims $claims): void {
    if ($claims->isSupport()) {
        header('X-Support-Session: ' . $claims->impersonationGrantId); // IMP-021 indicator
    }
    // ...load data, then $claims->requireOrganization($row['org_id'])
});
```

- For routes that never serve support sessions, `new RequestAuthenticator($introspector)`
  is enough. It rejects support tokens with 401.
- `$guard->authorize($raw, $operation, read: true)` accepts support tokens
  only. `$guard->authorizeAny(...)` accepts both kinds and is what
  `$guard->route($operation, $read)` uses.
- `read` must be `true` for an operation to count as a read; it defaults to
  `false` (a write). An operation whose name contains a write verb as a segment
  (`SupportOperations::WRITE_SEGMENTS`: `create`, `update`, `delete`, `cancel`,
  `issue` and so on) is always a write, even with `read: true`. Write allowlist
  entries match the whole operation name, case-insensitively.
- Protected operations (`SupportOperations::PROTECTED_OPERATIONS`: password,
  MFA, identifier and credential changes, API-key and personal-token creation,
  payments, refunds, ownership transfer, secrets, deletes, purges) are always
  denied to support sessions. Names are split into segments on `.`, `:` and
  `/`, case-insensitively, `-` read as `_`, and an entry matches when its
  segments appear anywhere in the name as a run, with or without a trailing
  `s` (`orders.delete`, `users.password.change`, `payments.create`,
  `refunds.issue`, `secrets.read`, `orders.purge` are protected;
  `secretary.list` is not). Add more with `protectedOperations`; the defaults
  can't be removed from a guard. A list passed as the second argument of
  `SupportOperations::isProtectedOperation($op, $list)` replaces the defaults,
  so pass `[...SupportOperations::PROTECTED_OPERATIONS, ...$yours]`. The Go and
  Node SDKs and the server's decision API apply the same rule; the shared
  cases are in `testdata/contracts/support-operations/cases.json`.
- When your service also calls the decision API with a support token as
  `subject_token`, keep the resource's `impersonation_policy.write_actions`
  equal to `writeOperations`.

## Bounded state

For a long-running PHP process that verifies JWTs locally:

```php
use ProudAuth\Sdk\BoundedState\BoundedState;
use ProudAuth\Sdk\BoundedState\BoundedVerifier;

$state = new BoundedState(
    baseUrl: 'https://id.example.com',
    realm: 'main',
    token: fn (): string => $serviceTokens->current(),   // admin audience, realm.session_events.read
    maxStalenessMs: 60_000,
);
$state->start();                                          // position at "now" before accepting traffic

// In a dedicated loop (a worker, a timer, a coroutine): long-polls with sync(20).
$state->run(
    function () use (&$shutdownRequested): bool { return $shutdownRequested; },   // by reference: re-read on every check
    fn (Throwable $e) => $log->warning('session events', ['category' => $e instanceof ProudAuth\Sdk\Verifier\VerifierException ? $e->errorCode->value : get_class($e)]),
);

// In the request path:
$authenticator = new BoundedVerifier($verifier, $state);  // offline verification, then revocation check
```

`start()` keeps the revocations already replayed and moves the position to
now. A `410 cursor_expired` rewinds to the oldest retained event and throws
`CursorExpiredException` from `sync()`; `run()` replays at once and keeps
following. The state is fresh only after a read reaches the end of the stream,
replays never weaken a revocation, and `user.recovery_restricted` is not a
revocation. `run()` stops when `$shouldStop` returns true; it checks before
every poll and every 100 ms of a backoff wait, but cannot interrupt a long poll
in flight (at most `waitSeconds`, 20 by default).

## Backend-for-frontend (BFF)

```php
use ProudAuth\Sdk\Oidc\AuthRequest;
use ProudAuth\Sdk\Oidc\FileRefreshLock;
use ProudAuth\Sdk\Oidc\OidcClient;
use ProudAuth\Sdk\Oidc\OidcErrorCode;
use ProudAuth\Sdk\Oidc\OidcException;
use ProudAuth\Sdk\Oidc\TokenSet;

$oidc = new OidcClient(
    issuer: 'https://id.example.com/realms/main',
    clientId: 'customer-web-bff',
    clientSecret: getenv('BFF_CLIENT_SECRET'),
    redirectUri: 'https://app.example.com/callback',
    scopes: ['openid', 'orders:read'],
    resource: 'https://api.example.com/orders',
);
session_start(); // server-side sessions; the default files handler locks each session per request

// GET /login
$ar = $oidc->authorizationUrl();                     // state, nonce, PKCE S256, resource
$_SESSION['login'] = $ar->toArray();                 // single use, server-side
header('Location: ' . $ar->url, true, 302);

// GET /callback
$ar = AuthRequest::fromArray($_SESSION['login'] ?? throw new RuntimeException('no login in progress'));
unset($_SESSION['login']);
// Validates state, iss (RFC 9207), redeems the code with the PKCE verifier, and validates the
// ID token (signature, iss, aud, azp, exp, nonce, at_hash). Pass the raw request target so
// duplicate parameters are detected ($_GET would hide them).
$result = $oidc->exchangeCode($ar, $_SERVER['REQUEST_URI']);
session_regenerate_id(true);
$_SESSION['tokens'] = $result->tokens->toArray();
$_SESSION['sub'] = $result->idClaims?->subject;

// Any API call
$session = $oidc->session(
    TokenSet::fromArray($_SESSION['tokens']),
    onRefresh: function (TokenSet $t): void { $_SESSION['tokens'] = $t->toArray(); }, // persist rotated tokens
);
try {
    $at = $session->accessToken();                   // refreshes once near expiry
    $res = call_api('https://api.example.com/orders', $at);
    if ($res->status === 401) {
        $res = call_api('https://api.example.com/orders', $session->accessToken(rejectedToken: $at));
    }
} catch (OidcException $e) {
    if ($e->errorCode !== OidcErrorCode::Reauthenticate) {
        throw $e;
    }
    unset($_SESSION['tokens']);                       // the user must log in again
}

// POST /logout: clears the session, revokes the refresh token, returns the RP-initiated logout URL.
$url = $oidc->logout($oidc->session(TokenSet::fromArray($_SESSION['tokens'])), postLogoutRedirectUri: 'https://app.example.com/');
session_destroy();
header('Location: ' . $url, true, 302);
```

**Refresh tokens rotate, and reusing one revokes the whole token family
(SES-007/008).** PHP serves concurrent requests of one browser session in
separate workers, each with its own `Session` object, so refreshes must be
serialized across them:

- PHP's default `files` session handler locks the session from
  `session_start()` until the request ends (or `session_write_close()`);
  storing the tokens there (as above) already serializes refreshes.
- Session handlers that do not lock (Redis without locking, cookies, a
  database) need `lock` and `reload`: `lock` runs the refresh while holding an
  exclusive lock for this browser session, and `reload` reads the stored tokens
  inside it, so a worker that waited uses the tokens another worker just
  rotated instead of presenting the old refresh token again:

  ```php
  $locks = new FileRefreshLock('/var/lib/myapp/locks');  // one host; use a distributed lock for several
  $session = $oidc->session($tokens,
      onRefresh: fn (TokenSet $t) => $store->save($sid, $t->toArray()),
      lock: $locks->for($sid),
      reload: fn (): ?TokenSet => ($a = $store->load($sid)) ? TokenSet::fromArray($a) : null);
  ```

- If a refresh fails, the session is cleared and the error is
  `reauthenticate`. A lost refresh response can't be retried safely.
- Never send refresh tokens or ID tokens to business APIs. `TokenSet` and
  `AuthRequest` hide their secrets from `var_dump()` and `print_r()`.

`OidcClient` also offers `discover()`, `validateIdToken($raw, nonce:,
accessToken:, maxAgeSec:)`, `revoke($token, $hint)` and `logoutUrl(...)`.
Pass a `Store` as `cache` to share the ID-token key set across requests.

## Admin client

```php
use ProudAuth\Sdk\Admin\AdminClient;
use ProudAuth\Sdk\Admin\ProblemException;
use ProudAuth\Sdk\Admin\RequestOptions;
use ProudAuth\Sdk\Admin\Secret;

$admin = new AdminClient(
    baseUrl: 'https://id.example.com',
    realm: 'main',
    token: fn (): string => get_admin_access_token(),   // or a string; called once per request
    timeoutMs: 30_000,
    userAgent: 'billing-provisioner/3.1',               // sent before "proudauth-sdk-php/0.2.0"
    onDeprecated: function (string $method, string $path, string $deprecation, ?string $sunset) use ($log): void {
        $log->warning('deprecated ProudAuth API', compact('method', 'path', 'deprecation', 'sunset')); // path without query
    },
);

foreach ($admin->users('ann') as $user) {            // follows next_cursor; stops on a cursor loop
    echo $user['id'], "\n";
}

try {
    $admin->createUser(['email' => 'a@example.com'], new RequestOptions(idempotencyKey: $savedKey)); // reuse the key when retrying
} catch (ProblemException $e) {
    error_log("{$e->status} {$e->errorCode} " . json_encode($e->errors)); // RFC 9457, e.g. type https://proudauth.com/problems/...
}

$res = $admin->getUser('usr_1');
$admin->updateUser('usr_1', ['display_name' => 'Ann'], new RequestOptions(ifMatch: $res->etag)); // 412 when stale

$created = $admin->createClient(['client_id' => 'svc', 'name' => 'Service', 'client_type' => 'confidential',
    'grant_types' => ['authorization_code'], 'redirect_uris' => ['https://svc.example.com/callback']]);
if ($created['client_secret'] instanceof Secret) {
    $vault->store('svc', $created['client_secret']->reveal());
}
print_r($created);                                    // [client_secret] => ProudAuth\Sdk\Admin\Secret Object ( [value] => [REDACTED] )
```

- `request($method, $path, $body, $options)` calls any route under
  `/api/v1/realms/{realm}`; `pages()` and `list()` iterate cursor-paginated
  lists as generators. Typed helpers cover users, organizations, members,
  invitations (also batches), roles and assignments, clients, credentials and
  resource grants, sessions, support grants, effective permissions and audit
  events, like the Node client.
- Responses are decoded into associative arrays (`AdminResponse::$data`). A
  `null` body sends nothing; an empty PHP array is sent as `{}`.
- One-time secrets in response data (`client_secret`, `client_secrets`,
  `api_key`, `signing_secret`, `setup_token`, `recovery_codes`,
  `invitation_secret`, `access_token`, `refresh_token`, `id_token`,
  `handoff_code`, `download_token`, `token`, `secret`, `webhook_secrets`, at
  any depth) are `Secret` objects: string conversion, `json_encode()`,
  `var_dump()`, `print_r()` and `var_export()` show `[REDACTED]` or nothing,
  `serialize()` refuses, and `reveal()` returns the value for the one place
  that must store it.
- Every request carries `ProudAuth-SDK: php/0.2.0` and a `User-Agent` ending
  in `proudauth-sdk-php/0.2.0`. Create requests (`createUser`,
  `createOrganization`, `invite`, `inviteBatch`) send a random
  `Idempotency-Key` unless you pass one.

## Security properties (offline verifier)

The `Verifier` implements the §14.4 algorithm:

1. **Issuer first.** The payload's `iss` must equal the configured issuer
   before any key lookup. Tokens from other issuers never trigger a network
   fetch (TEST-003).
2. **Strict parsing.**
   - Tokens over 8192 bytes are rejected.
   - The token must have exactly three canonical base64url segments, with no
     padding and nothing trailing.
   - JSON is parsed by the SDK's own RFC 8259 parser, not `json_decode()`
     (which silently keeps the last of duplicate members). Duplicate member
     names are rejected in the header and the payload, including escaped
     duplicates such as `"iss"`. Nesting deeper than 32 levels, invalid
     UTF-8, lone surrogates, non-finite numbers in claims and a BOM are
     rejected.
   - A `crit` header is rejected.
3. **Typing.** `typ` must be `at+jwt` or `application/at+jwt`
   (case-insensitive), so ID tokens are refused (TEST-002).
4. **Algorithm allowlist.** Only RS256, PS256, ES256 and EdDSA.
   - The SDK refuses to configure `none` or `HS*`.
   - The key type must match the algorithm, and a JWK `alg`, when present,
     must match the header.
   - RSA keys must be at least 2048 bits.
5. **Keys only from the configured JWKS.**
   - `jku`, `x5u` and an embedded `jwk` are ignored.
   - Public keys are built from the JWK members (RSA `n`/`e`, P-256 `x`/`y`,
     Ed25519 `x`) by encoding the SubjectPublicKeyInfo DER in the SDK; no
     certificate or PEM from the key set is parsed, and OpenSSL refuses P-256
     points that are not on the curve.
   - JWKS entries that are private, symmetric, not for signing (`use`,
     `key_ops`), on other curves or ambiguous (duplicate `kid`) are skipped.
   - An unknown `kid` triggers at most one refresh per `minRefreshIntervalMs`
     (default 30 s). Floods of random key IDs cause a bounded number of fetches
     (`$verifier->fetchCount()`, TEST-005); with a `Store`, across requests too.
   - If a refresh fails, the known keys are kept; a successful refresh
     replaces the set.
6. **Signatures.** RS256 with `openssl_verify()` (PKCS#1 v1.5); ES256 with
   `openssl_verify()` after converting the raw 64-byte `r || s` to DER
   (other lengths and `r` or `s` outside `[1, n-1]` are refused); EdDSA with
   libsodium; PS256 (which `openssl_verify()` cannot do) by the raw RSA
   operation through OpenSSL plus EMSA-PSS verification in the SDK with
   SHA-256, MGF1-SHA-256 and a 32-byte salt, checking every structural element.
   The tests run independent vectors for each algorithm (`tests/vectors`).
7. **Claims.**
   - The token must have exactly one audience, equal to the configured one
     (TEST-001).
   - `exp` is required. `nbf` and `iat` are checked when present. Clock skew
     defaults to 30 s and can't exceed 60 s (TEST-006).
   - `sub`, `client_id` and `jti` are required.
   - `token_kind` must be in the allowlist. The default is `user_access`,
     `service_access` and `exchange_access`.
8. **Fail closed.** Every failure throws, and a key-set outage becomes
   `unavailable` (503).

**Transport.** `CurlTransport` speaks only HTTP and HTTPS, verifies TLS
certificates and host names, never follows redirects (requests carry
credentials; the SDK also refuses 301, 302, 303, 307 and 308 from any
transport), enforces a deadline per request (JWKS 5 s, introspection 3 s, OIDC
10 s, admin 30 s, session events 30 s) and stops reading bodies over the limit
(JWKS, discovery and token responses 1 MiB, introspection 64 KiB, session
events 8 MiB, admin 32 MiB). Configured URLs must be absolute `http(s)` URLs
without credentials; they are parsed strictly and re-serialized before use.
Implement `ProudAuth\Sdk\Http\Transport` to use another HTTP client, with the
same contract (see its doc comment).

## Differences from the Node.js SDK

The PHP SDK has the Node SDK's behavior unless listed here.

- **No asynchronous API.** There are no `AbortSignal` options; deadlines are
  the configured timeouts. In-process "single-flight" coalescing does not
  apply (one PHP request has no concurrent callers), so:
  - the key-set cache can be shared across requests and workers with a
    `Store` (Node keeps it in its long-lived process);
  - OIDC sessions serialize refreshes across workers with PHP's session
    locking or the `lock` and `reload` options of `OidcClient::session()`;
  - `BoundedState::run()` takes a `$shouldStop` callback instead of a signal.
- **Request helpers** replace the Express, `node:http` and Fastify adapters:
  `RequestAuthenticator::authenticate()` (header value),
  `authenticateGlobals()` and `protect()` (superglobals), `Challenge`, and
  `SupportGuard::route()` for `guard.middleware()`. In `protect()`, a
  `VerifierException` thrown by the handler (for example by
  `requireScope()`) is answered with its challenge (403, 503, …); Node's
  `protect` answers 500. `Claims::requireScope()` records the required scopes
  on the exception so the challenge can advertise them. An empty list of
  Authorization header values (PSR-7's `getHeader()` for an absent header)
  means no header.
- **Durations are milliseconds** as in Node (`clockSkewMs`, `timeoutMs`, …);
  the injectable clock `now` returns milliseconds since the epoch. Dates are
  `DateTimeImmutable` in UTC.
- **Stricter JWK import.** Key members must be canonical base64url, P-256
  coordinates and Ed25519 keys exactly 32 bytes, RSA moduli at most 16384
  bits and RSA exponents odd, at least 3 and at most 64 bits. Keys outside
  these limits are skipped (fail closed) where Node might import them.
- **Bounded state.** Token-source, transport and response-parsing failures
  are `unavailable` `VerifierException`s (Node lets the raw error through).
  Requests have a 30 s deadline and an 8 MiB response limit (as in Go; Node
  has neither).
- **Admin client.** There is no `aborted` error code. `onDeprecated` receives
  `($method, $path, $deprecation, $sunset)`. Responses are associative arrays
  (an empty JSON object decodes to `[]`). `Secret` objects refuse
  `serialize()` and cloning.
- **OIDC callbacks** may be a full URL, a request target, a query string or a
  parameter array; in an array, a list value counts as a duplicate parameter.
  `AuthRequest` and `TokenSet` add `toArray()`/`fromArray()` for server-side
  storage.
- **Lowercasing.** Operation names are lowercased like JavaScript's
  `toLowerCase()` with ext-mbstring; without it, ASCII letters and the Kelvin
  sign (the only non-ASCII letter whose lowercase is ASCII) are folded, so
  the default lists still match exactly but custom non-ASCII names compare
  case-sensitively.

## Supported versions

| Requirement | Declared | Tested with |
| --- | --- | --- |
| PHP | `>=8.2` | 8.5.8 on macOS only. The source is checked for syntax and functions newer than 8.2, but 8.2 to 8.4 are not run. |
| ext-openssl | OpenSSL 1.1.1 or 3.x | OpenSSL 3.6.3 |
| ext-sodium | libsodium 1.0.x | libsodium 1.0.22 |
| ext-curl | libcurl 7.x or 8.x | libcurl 8.21.0 |
| ext-json | bundled | bundled |
| ext-mbstring | optional | loaded |

Version policy, security updates and the 0.2.0 changes are those of the other
SDKs: [docs/integrations/sdk-compatibility.md](https://proudauth.com/docs/integrations/sdk-compatibility/).
No test runs this SDK against a ProudAuth server yet; its tests use in-process
fakes and a local `php -S` server.

## Development

The tests need no Composer and no network:

```sh
php -d error_reporting=-1 -d display_errors=1 tests/run.php           # all tests
php tests/run.php Verifier                                             # classes or methods matching "Verifier"
```

`tests/run.php` is a small self-contained runner (`tests/bootstrap.php`
autoloads the SDK and the tests). Every PHP warning, notice or deprecation
fails the test that raised it, and the exit status is non-zero when any test
fails. The suites cover:

- the shared access-token fixtures (`testdata/contracts/access-tokens/cases.json`,
  every case with the expected category) and the shared support-operation
  fixtures (`testdata/contracts/support-operations/cases.json`, classification and
  `SupportGuard` decisions), like the Go and Node SDKs;
- independent ES256, PS256, RS256 and EdDSA signature vectors and the DER
  encoding of every key type (`tests/vectors`, test-only keys);
- the Node SDK's negative scenarios for the verifier, introspection and the
  support contract, bounded state, the OIDC client (against an in-process IdP
  that revokes the token family on refresh-token reuse), the admin client and
  the request helpers;
- `CurlTransport` and the request helpers over real sockets, against a
  `php -S` server the runner starts on 127.0.0.1 (redirects, deadlines, body
  limits, protocol restrictions, RFC 6750 responses).

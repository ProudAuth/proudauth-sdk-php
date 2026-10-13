<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Introspection;

use ProudAuth\Sdk\Internal\Text;
use ProudAuth\Sdk\Verifier\Authenticator;
use ProudAuth\Sdk\Verifier\Claims;
use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Implements the downstream support-access contract (§16.2, INT-010):
 * strict-online validation per request, preserved actor identity, read-only
 * default, explicit write allowlist, protected identity operations always
 * denied, and an audit record before access.
 */
final class SupportGuard
{
    /** @var (\Closure(SupportEvent): void)|null */
    private readonly ?\Closure $record;
    /** @var array<string, true> */
    private readonly array $writeOps;
    /** @var list<string> */
    private readonly array $protected;

    /**
     * @param Introspector|null                                   $introspector       required (contract)
     * @param SupportAuditor|(\Closure(SupportEvent): void)|null  $auditor            required (contract); called before access
     * @param list<string>                                        $writeOperations    operations allowed for allowlisted_write grants
     *                                                                                (IMP-011), matched case-insensitively against the
     *                                                                                whole name; default none
     * @param list<string>                                        $protectedOperations additional protected operations; the defaults
     *                                                                                cannot be removed
     *
     * @throws VerifierException contract, when the introspector or the auditor is missing
     */
    public function __construct(
        private readonly ?Introspector $introspector,
        SupportAuditor|\Closure|null $auditor,
        array $writeOperations = [],
        array $protectedOperations = [],
    ) {
        if ($auditor instanceof SupportAuditor) {
            $this->record = $auditor->recordSupportAccess(...);
        } else {
            $this->record = $auditor;
        }
        $ops = [];
        foreach ($writeOperations as $op) {
            $ops[Text::lower(Text::trim((string) $op))] = true;
        }
        $this->writeOps = $ops;
        $this->protected = [...SupportOperations::PROTECTED_OPERATIONS, ...array_map('strval', array_values($protectedOperations))];
        $this->validate();
    }

    /**
     * Checks the guard configuration (contract validation).
     *
     * @throws VerifierException contract
     */
    public function validate(): void
    {
        if ($this->introspector === null || $this->record === null) {
            throw new VerifierException(VerifierErrorCode::Contract);
        }
    }

    /**
     * Validates a support token for one operation. The audit record is written
     * before access is granted; if it cannot be written, access is denied
     * (unavailable). Policy denials are audited too and throw support_policy.
     *
     * @param bool $read true only for non-mutating operations; anything else is a
     *                   write, and so is an operation whose name carries a write verb
     *
     * @throws VerifierException
     */
    public function authorize(string $raw, string $operation, bool $read = false): Claims
    {
        $this->validate();
        return $this->decide($this->introspect($raw), $operation, $read);
    }

    /**
     * Single-introspection entry point for APIs that serve both ordinary and
     * support requests: ordinary tokens are checked against the Introspector's
     * accepted kinds, support tokens against the full support contract. The
     * decision is based on the authoritative token_kind, never on the token's
     * prefix.
     *
     * @throws VerifierException
     */
    public function authorizeAny(string $raw, string $operation, bool $read = false): Claims
    {
        $this->validate();
        $c = $this->introspect($raw);
        if ($c->tokenKind === Introspector::SUPPORT_TOKEN_KIND) {
            return $this->decide($c, $operation, $read);
        }
        if (!$this->acceptsKind($c->tokenKind)) {
            throw new VerifierException(VerifierErrorCode::TokenKind);
        }
        return $c;
    }

    /**
     * An Authenticator for one route operation using authorizeAny(), for
     * RequestAuthenticator (the counterpart of the Node SDK's
     * guard.middleware({operation, read})): 401 invalid token, 403 support
     * policy, 503 unavailable or audit failure.
     *
     * @throws \InvalidArgumentException when the operation is empty
     */
    public function route(string $operation, bool $read = false): Authenticator
    {
        if ($operation === '') {
            throw new \InvalidArgumentException('introspection: route operation is required');
        }
        return new RouteAuthenticator($this, $operation, $read);
    }

    private function introspect(string $raw): Claims
    {
        $introspector = $this->introspector;
        // Introspector::introspect() is private: it skips the token-kind policy and
        // must not be reachable from application code (the Node SDK uses a
        // module-private WeakMap for the same purpose).
        $fn = \Closure::bind(static fn (Introspector $i, string $r): Claims => $i->introspect($r), null, Introspector::class);
        return $fn($introspector, $raw);
    }

    private function acceptsKind(string $kind): bool
    {
        $fn = \Closure::bind(static fn (Introspector $i, string $k): bool => $i->acceptsKind($k), null, Introspector::class);
        return $fn($this->introspector, $kind);
    }

    private function decide(Claims $c, string $operation, bool $read): Claims
    {
        if ($c->tokenKind !== Introspector::SUPPORT_TOKEN_KIND || $c->actor === null || $c->actor->subject === '' || $c->impersonationGrantId === '') {
            // Never grant authority just because an actor claim exists, and never serve a
            // support request whose actor cannot be attributed (IMP-006, TEST-045).
            throw new VerifierException(VerifierErrorCode::TokenKind);
        }
        if (Text::trim($operation) === '') {
            throw new VerifierException(VerifierErrorCode::SupportPolicy);
        }
        $effectiveRead = $read && !SupportOperations::isWriteOperation($operation);
        $denyReason = null;
        if (SupportOperations::isProtectedOperation($operation, $this->protected)) {
            $denyReason = SupportEvent::DENY_PROTECTED_OPERATION;
        } elseif (!$effectiveRead && ($c->supportMode !== 'allowlisted_write' || !isset($this->writeOps[Text::lower(Text::trim($operation))]))) {
            $denyReason = SupportEvent::DENY_WRITE_NOT_ALLOWLISTED;
        }
        $allowed = $denyReason === null;
        $event = new SupportEvent(
            grantId: $c->impersonationGrantId,
            actor: $c->actor->subject,
            actorIssuer: $c->actor->issuer,
            subject: $c->subject,
            orgId: $c->orgId,
            clientId: $c->clientId,
            tokenId: $c->jti,
            operation: $operation,
            read: $effectiveRead,
            allowed: $allowed,
            denyReason: $denyReason,
            at: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        try {
            ($this->record)($event);
        } catch (\Throwable $cause) {
            // Durable audit before access (IMP-020): no record, no access.
            throw new VerifierException(VerifierErrorCode::Unavailable, $cause);
        }
        if (!$allowed) {
            throw new VerifierException(VerifierErrorCode::SupportPolicy);
        }
        return $c;
    }
}

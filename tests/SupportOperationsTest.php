<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Introspection\Introspector;
use ProudAuth\Sdk\Introspection\SupportEvent;
use ProudAuth\Sdk\Introspection\SupportGuard;
use ProudAuth\Sdk\Introspection\SupportOperations;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;

/**
 * The support-operation table shared with the Go and Node SDKs and the server
 * (sdk/fixtures/support-operations/cases.json), so every guard classifies
 * every operation identically. Port of sdk/node/test/support-operations.test.ts.
 */
final class SupportOperationsTest extends TestCase
{
    private const PATH = __DIR__ . '/../testdata/contracts/support-operations/cases.json';
    private const ISS = 'https://id.test/realms/main';
    private const AUD = 'https://api.test/orders';

    /** The token is echoed as the support mode. */
    private static function idp(): FakeTransport
    {
        return new FakeTransport(static function (Request $r): Response {
            $mode = FakeTransport::form($r->body)['token'] ?? '';
            return FakeTransport::json(200, [
                'active' => true, 'iss' => self::ISS, 'aud' => self::AUD, 'sub' => 'usr_customer', 'client_id' => 'support-bff',
                'token_kind' => 'impersonation_access', 'act' => ['sub' => 'usr_agent'], 'impersonation_grant_id' => 'imp_1',
                'support_mode' => $mode, 'jti' => 'tok_support_1', 'org_id' => 'org_a',
            ]);
        });
    }

    private static function introspector(): Introspector
    {
        return new Introspector(endpoint: 'https://id.test/realms/main/oauth/introspect', clientId: 'rs', clientSecret: 's', issuer: self::ISS, audience: self::AUD, transport: self::idp());
    }

    public function testClassifiesOperationsLikeTheGoAndNodeSdks(): void
    {
        $fx = FixturesTest::load(self::PATH);
        self::assertTrue(count($fx['cases']) > 0);
        self::assertTrue(count($fx['classification_only']) > 0);
        foreach ([...$fx['classification_only'], ...$fx['cases']] as $c) {
            self::assertSame($c['protected'], SupportOperations::isProtectedOperation($c['operation']), 'isProtectedOperation(' . json_encode($c['operation']) . "): {$c['why']}");
            self::assertSame($c['write'], SupportOperations::isWriteOperation($c['operation']), 'isWriteOperation(' . json_encode($c['operation']) . "): {$c['why']}");
        }
    }

    public function testReachesTheSameSupportGuardDecisionsAsTheGoAndNodeSdks(): void
    {
        $fx = FixturesTest::load(self::PATH);
        foreach ($fx['cases'] as $c) {
            $events = [];
            $guard = new SupportGuard(
                introspector: self::introspector(),
                auditor: static function (SupportEvent $ev) use (&$events): void {
                    $events[] = $ev;
                },
                writeOperations: $fx['write_operations'],
            );
            $label = "{$c['operation']} read=" . json_encode($c['read']) . " {$c['support_mode']}: {$c['why']}";
            if ($c['expect'] === 'allow') {
                $claims = $guard->authorize($c['support_mode'], $c['operation'], $c['read']);
                self::assertTrue($claims->isSupport(), $label);
            } else {
                self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize($c['support_mode'], $c['operation'], $c['read']), $label);
            }
            self::assertCount(1, $events, $label);
            $ev = $events[0];
            self::assertSame($c['expect'] === 'allow', $ev->allowed, $label);
            self::assertSame($c['expect'] === 'allow' ? null : $c['expect'], $ev->denyReason, $label);
            self::assertSame($c['read'] && !$c['write'], $ev->read, $label);
            self::assertSame('usr_agent', $ev->actor, $label);
            self::assertSame($c['operation'], $ev->operation, $label);
        }
    }

    public function testDeniesAnEmptyOperationWithoutAuditing(): void
    {
        $events = [];
        $guard = new SupportGuard(self::introspector(), static function (SupportEvent $ev) use (&$events): void {
            $events[] = $ev;
        });
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('read_only', '  ', true));
        self::assertVerifierError(E::SupportPolicy, static fn () => $guard->authorize('read_only', "\u{00A0}\u{3000}", true));
        self::assertCount(0, $events);
        self::assertTrue(SupportOperations::isProtectedOperation(''));
        self::assertTrue(SupportOperations::isProtectedOperation(' ..:: '));
    }

    public function testMatchesJavascriptCaseFolding(): void
    {
        // U+212A KELVIN SIGN lowercases to "k" in JavaScript, so this is api_key.create.
        self::assertTrue(SupportOperations::isProtectedOperation("api_\u{212A}ey.create"));
        self::assertTrue(SupportOperations::isWriteOperation("orders.\u{212A}LOCK") === false);
        self::assertTrue(SupportOperations::isWriteOperation("orders.LOC\u{212A}"));
        self::assertTrue(SupportOperations::isProtectedOperation("  Payments.Create\u{2003}"));
        self::assertFalse(SupportOperations::isProtectedOperation('secretary.list'));
        self::assertTrue(SupportOperations::isProtectedOperation('orders.export', ['orders.export']));
        self::assertFalse(SupportOperations::isProtectedOperation('orders.delete', ['orders.export']), 'an explicit list replaces the defaults');
        // Without ext-mbstring, ASCII names (and the Kelvin sign) still fold exactly.
        self::assertSame('api_key.create', \ProudAuth\Sdk\Internal\Text::lowerWithoutMbstring("API_\u{212A}EY.Create"));
        self::assertSame('orders.list', \ProudAuth\Sdk\Internal\Text::lowerWithoutMbstring('Orders.LIST'));
    }
}

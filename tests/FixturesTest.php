<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Http\Request;
use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Verifier\Verifier;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Shared verification fixtures (SDK-009): the same accepted and rejected
 * tokens the Go and Node SDKs check (sdk/fixtures/access-tokens/cases.json),
 * so all SDKs agree on every outcome. Port of sdk/node/test/fixtures.test.ts.
 */
final class FixturesTest extends TestCase
{
    public const PATH = __DIR__ . '/../testdata/contracts/access-tokens/cases.json';

    /** @return array<string, mixed> */
    public static function load(string $path): array
    {
        $raw = file_get_contents($path);
        if ($raw === false) {
            self::fail("cannot read {$path}");
        }
        return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    }

    public function testReproducesEveryAcceptedAndRejectedOutcome(): void
    {
        $fx = self::load(self::PATH);
        $jwks = new FakeTransport(static fn (Request $r): Response => FakeTransport::json(200, $fx['jwks']));
        $v = new Verifier(
            issuer: $fx['issuer'],
            audience: $fx['audience'],
            jwksUrl: 'https://fixtures.test/jwks',
            now: static fn (): int => $fx['now'] * 1000,
            minRefreshIntervalMs: 1000,
            transport: $jwks,
        );
        self::assertTrue(count($fx['cases']) >= 18, 'all fixture cases are present');
        $accepted = 0;
        foreach ($fx['cases'] as $c) {
            try {
                $v->verify($c['token']);
                self::assertSame($c['expect'], 'accept', "{$c['name']}: accepted, want {$c['expect']} ({$c['why']})");
                $accepted++;
            } catch (VerifierException $e) {
                self::assertSame($c['expect'], $e->errorCode->value, "{$c['name']}: got {$e->errorCode->value}, want {$c['expect']} ({$c['why']})");
            }
        }
        self::assertSame(count(array_filter($fx['cases'], static fn (array $c): bool => $c['expect'] === 'accept')), $accepted);
    }

    public function testFixtureKeysHaveTheExpectedTypes(): void
    {
        $fx = self::load(self::PATH);
        $types = array_map(static fn (array $k): string => $k['kty'] . '/' . $k['alg'], $fx['jwks']['keys']);
        sort($types);
        self::assertSame(['OKP/EdDSA', 'RSA/RS256'], $types);
    }
}

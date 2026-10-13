<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Tests\Support\Jwt;
use ProudAuth\Sdk\Tests\Support\TestKey;
use ProudAuth\Sdk\Verifier\IssuerRegistration;
use ProudAuth\Sdk\Verifier\MultiIssuerVerifier;
use ProudAuth\Sdk\Verifier\Verifier;
use ProudAuth\Sdk\Verifier\VerifierErrorCode as E;

/**
 * Port of sdk/node/test/multi-issuer.test.ts (INT-009).
 */
final class MultiIssuerTest extends TestCase
{
    private const AUD = 'https://api.test/orders';

    /** @var array<string, TestKey> */
    private static array $keys = [];

    public static function setUpBeforeClass(): void
    {
        self::$keys = [
            'https://id.test/realms/acme' => TestKey::make('ES256', 'a1'),
            'https://id.test/realms/globex' => TestKey::make('ES256', 'b1'),
            'https://rogue.test' => TestKey::make('ES256', 'r1'),
        ];
    }

    private static function token(string $iss): string
    {
        $now = time();
        return Jwt::sign(self::$keys[$iss], ['iss' => $iss, 'sub' => 'usr_same', 'aud' => self::AUD, 'client_id' => 'web', 'iat' => $now, 'exp' => $now + 300, 'jti' => 'j', 'scope' => 'orders:read', 'token_kind' => 'user_access']);
    }

    private static function verifier(string $iss): Verifier
    {
        $jwk = self::$keys[$iss]->jwk;
        return new Verifier(issuer: $iss, audience: self::AUD, jwksUrl: $iss . '/jwks', transport: new FakeTransport(static fn (): Response => FakeTransport::json(200, ['keys' => [$jwk]])));
    }

    public function testVerifiesRegisteredIssuersWithTheirTenantAndRefusesOthers(): void
    {
        [$a, $b, $rogue] = array_keys(self::$keys);
        $m = new MultiIssuerVerifier([
            $a => new IssuerRegistration(self::verifier($a), 'acme'),
            $b => new IssuerRegistration(self::verifier($b), 'globex'),
        ]);
        $ta = $m->verifyTenant(self::token($a));
        self::assertSame('acme', $ta->tenant);
        self::assertSame('usr_same', $ta->claims->subject);
        self::assertSame('globex', $m->verifyTenant(self::token($b))->tenant);
        self::assertSame('usr_same', $m->authenticate(self::token($b))->subject);
        self::assertVerifierError(E::Issuer, static fn () => $m->verifyTenant(self::token($rogue)));
        self::assertVerifierError(E::Malformed, static fn () => $m->authenticate('not-a-jwt'));
        self::assertVerifierError(E::Malformed, static fn () => $m->authenticate('a.' . Jwt::b64('{"iss":7}') . '.c'));
        self::assertVerifierError(E::Malformed, static fn () => $m->authenticate('a.' . Jwt::b64('[1]') . '.c'));
        self::assertVerifierError(E::Malformed, static fn () => $m->authenticate(str_repeat('a', 17_000)));
        // A token signed by acme's key but claiming globex is refused by globex's verifier.
        $forged = Jwt::sign(self::$keys[$a], ['iss' => $b, 'sub' => 'usr_same', 'aud' => self::AUD, 'client_id' => 'web', 'exp' => time() + 300, 'jti' => 'j', 'token_kind' => 'user_access'], ['kid' => 'b1']);
        self::assertVerifierError(E::Signature, static fn () => $m->verifyTenant($forged));
        self::assertThrows(\InvalidArgumentException::class, static fn () => new MultiIssuerVerifier([$b => new IssuerRegistration(self::verifier($a), 'x')]), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'exactly that issuer'));
        self::assertThrows(\InvalidArgumentException::class, static fn () => new MultiIssuerVerifier([$a => new IssuerRegistration(self::verifier($a), '')]));
        self::assertThrows(\InvalidArgumentException::class, static fn () => new MultiIssuerVerifier([]), static fn (\Throwable $e): bool => str_contains($e->getMessage(), 'at least one'));
    }
}

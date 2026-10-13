<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Http\Response;
use ProudAuth\Sdk\Internal\Jose\PublicKey;
use ProudAuth\Sdk\Internal\Jose\Signature;
use ProudAuth\Sdk\Internal\Json\StrictJson;
use ProudAuth\Sdk\Tests\Support\FakeTransport;
use ProudAuth\Sdk\Verifier\Verifier;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * Independent signature vectors (tests/vectors/signatures.json), generated
 * with Go's crypto/ecdsa, crypto/rsa and crypto/ed25519 and cross-checked
 * with the openssl CLI: valid, tampered, wrong-key and malformed signatures
 * for ES256, PS256, RS256 and EdDSA, the SubjectPublicKeyInfo Go encodes for
 * each key, and end-to-end access tokens.
 */
final class CryptoVectorsTest extends TestCase
{
    private const PATH = __DIR__ . '/vectors/signatures.json';

    /** @var array<string, mixed> */
    private static array $fx;
    /** @var array<string, PublicKey|null> */
    private static array $keys = [];

    public static function setUpBeforeClass(): void
    {
        self::$fx = FixturesTest::load(self::PATH);
        foreach (self::$fx['keys'] as $k) {
            self::$keys[$k['kid']] = PublicKey::fromJwk(StrictJson::decode(json_encode($k['jwk'], JSON_THROW_ON_ERROR)));
        }
    }

    private static function b64u(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/'), true);
    }

    public function testEncodesTheSameSubjectPublicKeyInfoAsGo(): void
    {
        foreach (self::$fx['keys'] as $k) {
            $key = self::$keys[$k['kid']];
            if ($k['kid'] === 'rs-vec-1024') {
                self::assertNull($key, 'RSA keys shorter than 2048 bits are skipped');
                continue;
            }
            self::assertInstanceOf(PublicKey::class, $key, $k['kid']);
            self::assertSame($k['spki_der_b64'], base64_encode($key->spki), "{$k['kid']}: DER SubjectPublicKeyInfo");
            if ($k['kind'] === 'RSA') {
                self::assertSame($k['bits'], $key->rsaBits, $k['kid']);
            }
        }
    }

    public function testVerifiesEverySignatureVectorLikeOpenSsl(): void
    {
        $byAlg = [];
        foreach (self::$fx['signatures'] as $v) {
            $key = self::$keys[$v['kid']];
            self::assertInstanceOf(PublicKey::class, $key, $v['name']);
            $sig = self::b64u($v['signature']);
            self::assertSame($v['valid'], Signature::verify($v['alg'], $key, $v['input'], $sig), "{$v['name']}: {$v['why']}");
            $byAlg[$v['alg']][$v['valid'] ? 'valid' : 'invalid'] = ($byAlg[$v['alg']][$v['valid'] ? 'valid' : 'invalid'] ?? 0) + 1;
        }
        foreach (['ES256', 'PS256', 'RS256', 'EdDSA'] as $alg) {
            self::assertTrue(($byAlg[$alg]['valid'] ?? 0) >= 1 && ($byAlg[$alg]['invalid'] ?? 0) >= 4, "{$alg} has valid and invalid vectors");
        }
    }

    public function testEmitsNoPhpWarningsOnAnyFailurePath(): void
    {
        // Signature::verify() turns exceptions into false, so record diagnostics
        // instead of throwing them to prove that no failure path warns.
        $raised = [];
        set_error_handler(static function (int $no, string $msg) use (&$raised): bool {
            $raised[] = $msg;
            return true;
        });
        try {
            foreach (self::$fx['signatures'] as $v) {
                Signature::verify($v['alg'], self::$keys[$v['kid']], $v['input'], self::b64u($v['signature']));
                foreach (['ES256', 'PS256', 'RS256', 'EdDSA'] as $alg) {
                    Signature::verify($alg, self::$keys[$v['kid']], $v['input'], self::b64u($v['signature']) . "\0");
                }
            }
            foreach (self::$fx['keys'] as $k) {
                PublicKey::fromJwk(StrictJson::decode(json_encode(['kty' => $k['kind'], 'kid' => 'x', 'crv' => 'P-256', 'n' => 'AQAB', 'e' => 'AQAB', 'x' => 'AA', 'y' => 'AA'])));
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $raised);
    }

    public function testNeverVerifiesWithAKeyOfTheWrongType(): void
    {
        foreach (self::$fx['signatures'] as $v) {
            if (!$v['valid']) {
                continue;
            }
            $sig = self::b64u($v['signature']);
            foreach (['ES256', 'PS256', 'RS256', 'EdDSA', 'none', 'HS256'] as $alg) {
                if ($alg !== $v['alg']) {
                    self::assertFalse(Signature::verify($alg, self::$keys[$v['kid']], $v['input'], $sig), "{$v['name']} as {$alg}");
                }
            }
        }
    }

    public function testConvertsOnlyWellFormedEs256Signatures(): void
    {
        $n = hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
        $one = str_repeat("\0", 31) . "\x01";
        self::assertSame("\x30\x06\x02\x01\x01\x02\x01\x01", Signature::ecdsaRawToDer($one . $one));
        $high = str_repeat("\x80", 32);
        self::assertSame("\x30\x46\x02\x21\x00" . $high . "\x02\x21\x00" . $high, Signature::ecdsaRawToDer($high . $high));
        $nMinus1 = substr($n, 0, 31) . "\x50";
        self::assertTrue(Signature::ecdsaRawToDer($nMinus1 . $one) !== null);
        self::assertNull(Signature::ecdsaRawToDer($n . $one));
        self::assertNull(Signature::ecdsaRawToDer($one . $n));
        self::assertNull(Signature::ecdsaRawToDer(str_repeat("\0", 32) . $one));
        self::assertNull(Signature::ecdsaRawToDer($one . str_repeat("\0", 32)));
        self::assertNull(Signature::ecdsaRawToDer($one . $one . "\0"));
        self::assertNull(Signature::ecdsaRawToDer(substr($one . $one, 1)));
    }

    public function testAcceptsAndRejectsTheEndToEndTokensLikeTheVectors(): void
    {
        $jwks = ['keys' => array_map(static fn (array $k): array => $k['jwk'], self::$fx['keys'])];
        $v = new Verifier(
            issuer: self::$fx['issuer'],
            audience: self::$fx['audience'],
            jwksUrl: 'https://vectors.test/jwks',
            now: static fn (): int => self::$fx['now'] * 1000,
            transport: new FakeTransport(static fn (): Response => FakeTransport::json(200, $jwks)),
        );
        foreach (self::$fx['tokens'] as $c) {
            try {
                $claims = $v->verify($c['token']);
                self::assertSame($c['expect'], 'accept', "{$c['name']}: accepted ({$c['why']})");
                self::assertSame('usr_vec', $claims->subject);
            } catch (VerifierException $e) {
                self::assertSame($c['expect'], $e->errorCode->value, "{$c['name']}: {$c['why']}");
            }
        }
    }
}

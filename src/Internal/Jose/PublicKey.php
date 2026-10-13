<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Jose;

use ProudAuth\Sdk\Internal\Base64Url;
use ProudAuth\Sdk\Internal\Json\JsonObject;

/**
 * One public verification key imported from a JWK. The SubjectPublicKeyInfo
 * is encoded here from the JWK members (RSA n/e, P-256 x/y, Ed25519 x), so no
 * certificate or PEM from the key set is ever parsed.
 *
 * @internal
 */
final class PublicKey
{
    public const MIN_RSA_BITS = 2048;
    public const MAX_RSA_BITS = 16384;

    private const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    private function __construct(
        public readonly string $kid,
        /** The JWK "alg" member, when the key set declares one. */
        public readonly ?string $alg,
        /** RSA, EC (P-256 only) or OKP (Ed25519 only). */
        public readonly string $kty,
        /** DER SubjectPublicKeyInfo. */
        public readonly string $spki,
        /** Modulus length in bits (RSA keys only, else 0). */
        public readonly int $rsaBits,
        private readonly ?\OpenSSLAsymmetricKey $handle,
        private readonly string $ed25519,
    ) {
    }

    /**
     * Imports one public verification key. Keys without a kid, keys not meant
     * for signatures, private or symmetric keys, unsupported key types and
     * curves, and RSA keys shorter than 2048 bits are skipped (null) rather
     * than trusted, as in the Node SDK.
     */
    public static function fromJwk(mixed $jwk): ?self
    {
        if (!$jwk instanceof JsonObject) {
            return null;
        }
        $kid = $jwk->get('kid');
        if (!is_string($kid) || $kid === '') {
            return null;
        }
        if ($jwk->has('use') && $jwk->get('use') !== 'sig') {
            return null;
        }
        if ($jwk->has('key_ops')) {
            $ops = $jwk->get('key_ops');
            if (!is_array($ops) || !in_array('verify', $ops, true)) {
                return null;
            }
        }
        $alg = null;
        if ($jwk->has('alg')) {
            $alg = $jwk->get('alg');
            if (!is_string($alg)) {
                return null;
            }
        }
        foreach (self::PRIVATE_MEMBERS as $m) {
            if ($jwk->has($m)) {
                return null;
            }
        }
        try {
            return match ($jwk->get('kty')) {
                'RSA' => self::rsa($jwk, $kid, $alg),
                'EC' => $jwk->get('crv') === 'P-256' ? self::p256($jwk, $kid, $alg) : null,
                'OKP' => $jwk->get('crv') === 'Ed25519' ? self::ed25519($jwk, $kid, $alg) : null,
                default => null,
            };
        } catch (\InvalidArgumentException) {
            return null;
        } finally {
            self::clearOpenSslErrors();
        }
    }

    private static function member(JsonObject $jwk, string $name): string
    {
        $v = $jwk->get($name);
        if (!is_string($v)) {
            throw new \InvalidArgumentException('missing member');
        }
        return Base64Url::decode($v);
    }

    private static function rsa(JsonObject $jwk, string $kid, ?string $alg): ?self
    {
        $n = ltrim(self::member($jwk, 'n'), "\0");
        $e = ltrim(self::member($jwk, 'e'), "\0");
        if ($n === '' || $e === '') {
            return null;
        }
        $bits = (strlen($n) - 1) * 8 + strlen(decbin(ord($n[0])));
        if ($bits < self::MIN_RSA_BITS || $bits > self::MAX_RSA_BITS) {
            return null;
        }
        // An odd public exponent of at least 3 and at most 64 bits (65537 in practice).
        if (strlen($e) > 8 || (ord($e[strlen($e) - 1]) & 1) === 0 || (strlen($e) === 1 && ord($e) < 3)) {
            return null;
        }
        $spki = Der::rsaSpki($n, $e);
        $handle = self::load($spki, OPENSSL_KEYTYPE_RSA);
        if ($handle === null) {
            return null;
        }
        return new self($kid, $alg, 'RSA', $spki, $bits, $handle, '');
    }

    private static function p256(JsonObject $jwk, string $kid, ?string $alg): ?self
    {
        $x = self::member($jwk, 'x');
        $y = self::member($jwk, 'y');
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            return null;
        }
        $spki = Der::p256Spki($x, $y);
        // OpenSSL refuses points that are not on the curve.
        $handle = self::load($spki, OPENSSL_KEYTYPE_EC);
        if ($handle === null) {
            return null;
        }
        $details = openssl_pkey_get_details($handle);
        if (!is_array($details) || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            return null;
        }
        return new self($kid, $alg, 'EC', $spki, 0, $handle, '');
    }

    private static function ed25519(JsonObject $jwk, string $kid, ?string $alg): ?self
    {
        $x = self::member($jwk, 'x');
        if (strlen($x) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return null;
        }
        return new self($kid, $alg, 'OKP', Der::ed25519Spki($x), 0, null, $x);
    }

    private static function load(string $spki, int $type): ?\OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public(Der::pem($spki));
        if ($key === false) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || ($details['type'] ?? null) !== $type) {
            return null;
        }
        return $key;
    }

    /** OpenSSL keeps a per-thread error queue; drain it so failures never leak into later calls. */
    public static function clearOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard
        }
    }

    public function openSslKey(): ?\OpenSSLAsymmetricKey
    {
        return $this->handle;
    }

    public function ed25519Key(): string
    {
        return $this->ed25519;
    }

    /** Never print key handles. */
    public function __debugInfo(): array
    {
        return ['kid' => $this->kid, 'alg' => $this->alg, 'kty' => $this->kty, 'rsaBits' => $this->rsaBits];
    }
}

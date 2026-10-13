<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Jose;

/**
 * JWS signature verification for the four asymmetric algorithms ProudAuth
 * issues (RS256, PS256, ES256, EdDSA/Ed25519). Verification only: the SDK
 * never signs. There is no "none", no HMAC and no algorithm fallback
 * (TOK-005). The key type must match the algorithm, so an RSA key can never
 * verify an ES256 token and vice versa.
 *
 * @internal
 */
final class Signature
{
    public const SUPPORTED_ALGORITHMS = ['RS256', 'PS256', 'ES256', 'EdDSA'];

    /** The order of the P-256 group. */
    private const P256_N = "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
        . "\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51";

    /**
     * Validates an algorithm allowlist (default: all supported). "none" and
     * symmetric algorithms are always refused.
     *
     * @param list<string>|null $algorithms
     *
     * @return array<string, true>
     *
     * @throws \InvalidArgumentException
     */
    public static function resolveAlgorithms(?array $algorithms, string $prefix): array
    {
        $list = $algorithms === null || $algorithms === [] ? self::SUPPORTED_ALGORITHMS : $algorithms;
        $set = [];
        foreach ($list as $a) {
            if (!is_string($a) || strtolower($a) === 'none' || preg_match('/^hs/i', $a) === 1) {
                $shown = is_scalar($a) ? (string) $a : get_debug_type($a);
                throw new \InvalidArgumentException("{$prefix}: algorithm {$shown} is not allowed (no symmetric or unsigned tokens)");
            }
            if (!in_array($a, self::SUPPORTED_ALGORITHMS, true)) {
                throw new \InvalidArgumentException("{$prefix}: algorithm {$a} is not supported (supported: " . implode(', ', self::SUPPORTED_ALGORITHMS) . ')');
            }
            $set[$a] = true;
        }
        return $set;
    }

    public static function verify(string $alg, PublicKey $key, string $data, string $signature): bool
    {
        try {
            return match ($alg) {
                'RS256' => self::rs256($key, $data, $signature),
                'PS256' => self::ps256($key, $data, $signature),
                'ES256' => self::es256($key, $data, $signature),
                'EdDSA' => self::eddsa($key, $data, $signature),
                default => false,
            };
        } catch (\Throwable) {
            return false;
        } finally {
            PublicKey::clearOpenSslErrors();
        }
    }

    /** RSASSA-PKCS1-v1_5 with SHA-256. */
    private static function rs256(PublicKey $key, string $data, string $signature): bool
    {
        $k = $key->openSslKey();
        if ($key->kty !== 'RSA' || $k === null || strlen($signature) !== intdiv($key->rsaBits + 7, 8)) {
            return false;
        }
        return openssl_verify($data, $signature, $k, OPENSSL_ALGO_SHA256) === 1;
    }

    /** RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt. */
    private static function ps256(PublicKey $key, string $data, string $signature): bool
    {
        $k = $key->openSslKey();
        if ($key->kty !== 'RSA' || $k === null) {
            return false;
        }
        return RsaPss::verify($k, $key->rsaBits, $data, $signature);
    }

    /**
     * ECDSA P-256 with SHA-256. JWS carries the raw 64-byte r || s (RFC 7518
     * §3.4); it is checked and converted to the DER form OpenSSL expects.
     */
    private static function es256(PublicKey $key, string $data, string $signature): bool
    {
        $k = $key->openSslKey();
        if ($key->kty !== 'EC' || $k === null) {
            return false;
        }
        $der = self::ecdsaRawToDer($signature);
        if ($der === null) {
            return false;
        }
        return openssl_verify($data, $der, $k, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Converts a JWS ES256 signature to an ASN.1 ECDSA-Sig-Value, or null when
     * it is not exactly 64 bytes or r or s is outside [1, n-1].
     */
    public static function ecdsaRawToDer(string $signature): ?string
    {
        if (strlen($signature) !== 64) {
            return null;
        }
        $r = substr($signature, 0, 32);
        $s = substr($signature, 32);
        $zero = str_repeat("\0", 32);
        // Equal-length big-endian byte strings compare like the integers they encode.
        if ($r === $zero || $s === $zero || strcmp($r, self::P256_N) >= 0 || strcmp($s, self::P256_N) >= 0) {
            return null;
        }
        return Der::sequence(Der::unsignedInteger($r), Der::unsignedInteger($s));
    }

    /** Ed25519 (RFC 8032) via libsodium. */
    private static function eddsa(PublicKey $key, string $data, string $signature): bool
    {
        $pk = $key->ed25519Key();
        if ($key->kty !== 'OKP' || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($signature, $data, $pk);
    }
}

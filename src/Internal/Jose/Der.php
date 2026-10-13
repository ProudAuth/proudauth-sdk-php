<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Jose;

/**
 * The few DER encodings the SDK needs: SubjectPublicKeyInfo for RSA, P-256
 * and Ed25519 public keys, and ECDSA-Sig-Value. Encoding only; the SDK never
 * parses DER from untrusted input.
 *
 * @internal
 */
final class Der
{
    /** rsaEncryption, 1.2.840.113549.1.1.1 */
    private const OID_RSA = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    /** id-ecPublicKey, 1.2.840.10045.2.1 */
    private const OID_EC = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    /** prime256v1 / secp256r1, 1.2.840.10045.3.1.7 */
    private const OID_P256 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    /** id-Ed25519, 1.3.101.112 */
    private const OID_ED25519 = "\x06\x03\x2b\x65\x70";

    public static function length(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $s = ltrim(pack('N', $n), "\0");
        return chr(0x80 | strlen($s)) . $s;
    }

    public static function tlv(int $tag, string $value): string
    {
        return chr($tag) . self::length(strlen($value)) . $value;
    }

    public static function sequence(string ...$items): string
    {
        return self::tlv(0x30, implode('', $items));
    }

    /** A non-negative INTEGER from big-endian magnitude bytes (minimal encoding). */
    public static function unsignedInteger(string $magnitude): string
    {
        $m = ltrim($magnitude, "\0");
        if ($m === '' || (ord($m[0]) & 0x80) !== 0) {
            $m = "\0" . $m;
        }
        return self::tlv(0x02, $m);
    }

    public static function bitString(string $bytes): string
    {
        return self::tlv(0x03, "\0" . $bytes);
    }

    public static function rsaSpki(string $n, string $e): string
    {
        $rsaPublicKey = self::sequence(self::unsignedInteger($n), self::unsignedInteger($e));
        return self::sequence(self::sequence(self::OID_RSA, "\x05\x00"), self::bitString($rsaPublicKey));
    }

    /** @param string $x 32 bytes, $y 32 bytes */
    public static function p256Spki(string $x, string $y): string
    {
        return self::sequence(self::sequence(self::OID_EC, self::OID_P256), self::bitString("\x04" . $x . $y));
    }

    /** @param string $x the 32-byte Ed25519 public key */
    public static function ed25519Spki(string $x): string
    {
        return self::sequence(self::sequence(self::OID_ED25519), self::bitString($x));
    }

    public static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Jose;

/**
 * RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) with SHA-256, MGF1-SHA-256 and a salt
 * length equal to the hash length (32 bytes), the parameters of JWS PS256
 * (RFC 7518 §3.5) and of the Node SDK, which verifies with
 * RSA_PSS_SALTLEN_DIGEST. openssl_verify() has no PSS mode, so the RSA
 * public operation is done with openssl_public_encrypt(OPENSSL_NO_PADDING)
 * (which rejects a signature representative >= n) and EMSA-PSS-VERIFY is
 * implemented here.
 *
 * Every structural element of the encoded message is checked (leading zero
 * bits, the 0xbc trailer, the all-zero padding, the 0x01 separator, the salt
 * length and the hash), and once the encoded message has been recovered all
 * checks run before the result is decided.
 *
 * @internal
 */
final class RsaPss
{
    private const HASH_LEN = 32;
    private const SALT_LEN = 32;

    public static function verify(\OpenSSLAsymmetricKey $key, int $modBits, string $message, string $signature): bool
    {
        $k = intdiv($modBits + 7, 8);
        if ($modBits < 2 || strlen($signature) !== $k) {
            return false;
        }
        // RSAVP1: m = s^e mod n. OpenSSL refuses s >= n.
        $em = '';
        if (!openssl_public_encrypt($signature, $em, $key, OPENSSL_NO_PADDING) || !is_string($em) || strlen($em) !== $k) {
            return false;
        }
        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);
        if ($emLen < self::HASH_LEN + self::SALT_LEN + 2) {
            return false;
        }

        $ok = 1;
        // I2OSP(m, emLen): when emLen < k the extra leading octet must be zero.
        $lead = $k - $emLen;
        $ok &= (int) hash_equals(str_repeat("\0", $lead), substr($em, 0, $lead));
        $em = substr($em, $lead);

        $ok &= (int) ($em[$emLen - 1] === "\xbc");
        $dbLen = $emLen - self::HASH_LEN - 1;
        $maskedDb = substr($em, 0, $dbLen);
        $h = substr($em, $dbLen, self::HASH_LEN);

        // The leftmost 8*emLen - emBits bits of maskedDB must be zero.
        $zeroBits = 8 * $emLen - $emBits;
        $topMask = (0xff << (8 - $zeroBits)) & 0xff;
        $ok &= (int) ((ord($maskedDb[0]) & $topMask) === 0);

        $db = $maskedDb ^ self::mgf1($h, $dbLen);
        $db[0] = chr(ord($db[0]) & (0xff >> $zeroBits));

        $psLen = $emLen - self::HASH_LEN - self::SALT_LEN - 2;
        $ok &= (int) hash_equals(str_repeat("\0", $psLen), substr($db, 0, $psLen));
        $ok &= (int) ($db[$psLen] === "\x01");
        $salt = substr($db, $psLen + 1);
        $ok &= (int) (strlen($salt) === self::SALT_LEN);

        $mHash = hash('sha256', $message, true);
        $h2 = hash('sha256', str_repeat("\0", 8) . $mHash . $salt, true);
        $ok &= (int) hash_equals($h2, $h);

        return $ok === 1;
    }

    /** MGF1 with SHA-256 (RFC 8017 §B.2.1). */
    private static function mgf1(string $seed, int $length): string
    {
        $out = '';
        for ($counter = 0; strlen($out) < $length; $counter++) {
            $out .= hash('sha256', $seed . pack('N', $counter), true);
        }
        return substr($out, 0, $length);
    }
}

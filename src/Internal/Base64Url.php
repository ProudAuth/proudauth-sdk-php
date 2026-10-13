<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

/**
 * @internal
 */
final class Base64Url
{
    /**
     * Strict, canonical base64url: no padding, no characters outside the
     * alphabet, no non-zero pad bits.
     *
     * @throws \InvalidArgumentException
     */
    public static function decode(string $s): string
    {
        if (strlen($s) % 4 === 1 || strspn($s, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_') !== strlen($s)) {
            throw new \InvalidArgumentException('invalid base64url');
        }
        $b = base64_decode(strtr($s, '-_', '+/'), true);
        if ($b === false || self::encode($b) !== $s) {
            throw new \InvalidArgumentException('non-canonical base64url');
        }
        return $b;
    }

    public static function encode(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }
}

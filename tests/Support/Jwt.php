<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests\Support;

/**
 * Test-only token construction.
 */
final class Jwt
{
    public static function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    /** Signs raw header and payload JSON text (lets tests craft duplicate members). */
    public static function signRaw(TestKey $key, string $headerJson, string $payloadJson, ?string $alg = null): string
    {
        $input = self::b64($headerJson) . '.' . self::b64($payloadJson);
        return $input . '.' . self::b64($key->sign($input, $alg ?? $key->alg));
    }

    /**
     * Signs a JWT. The header defaults to {alg, kid, typ: "at+jwt"}; members
     * set to null are left out (JavaScript's undefined).
     *
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $header
     */
    public static function sign(TestKey $key, array $payload, array $header = []): string
    {
        $h = self::omitNull(array_merge(['alg' => $key->alg, 'kid' => $key->kid, 'typ' => 'at+jwt'], $header));
        $alg = is_string($h['alg'] ?? null) ? $h['alg'] : $key->alg;
        return self::signRaw($key, self::encode($h), self::encode(self::omitNull($payload)), $alg);
    }

    public static function encode(mixed $v): string
    {
        return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /** @param array<string, mixed> $a */
    private static function omitNull(array $a): array
    {
        return array_filter($a, static fn (mixed $v): bool => $v !== null);
    }
}

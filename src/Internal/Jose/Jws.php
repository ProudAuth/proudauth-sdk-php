<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Jose;

use ProudAuth\Sdk\Internal\Base64Url;
use ProudAuth\Sdk\Internal\Json\JsonObject;
use ProudAuth\Sdk\Internal\Json\StrictJson;
use ProudAuth\Sdk\Internal\Json\StrictJsonException;

/**
 * A parsed compact JWS. Nothing in it is trusted until the signature has been
 * verified.
 *
 * @internal
 */
final class Jws
{
    private function __construct(
        public readonly JsonObject $header,
        public readonly JsonObject $payload,
        public readonly string $signingInput,
        public readonly string $signature,
    ) {
    }

    /**
     * Parses a compact JWS: exactly three canonical base64url segments; header
     * and payload must be JSON objects without duplicate members or trailing
     * data.
     *
     * @throws JwsException with reason "malformed" or "duplicate"
     */
    public static function parse(string $raw): self
    {
        $parts = explode('.', $raw);
        if (count($parts) !== 3) {
            throw new JwsException(JwsException::MALFORMED);
        }
        [$h, $p, $s] = $parts;
        try {
            $hb = Base64Url::decode($h);
            $pb = Base64Url::decode($p);
            $sig = Base64Url::decode($s);
        } catch (\InvalidArgumentException) {
            throw new JwsException(JwsException::MALFORMED);
        }
        $header = self::segment($hb);
        $payload = self::segment($pb);
        return new self($header, $payload, $h . '.' . $p, $sig);
    }

    private static function segment(string $bytes): JsonObject
    {
        try {
            $v = StrictJson::decode($bytes);
        } catch (StrictJsonException $e) {
            throw new JwsException($e->reason === StrictJsonException::DUPLICATE ? JwsException::DUPLICATE : JwsException::MALFORMED);
        }
        if (!$v instanceof JsonObject) {
            throw new JwsException(JwsException::MALFORMED);
        }
        return $v;
    }
}

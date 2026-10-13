<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

/**
 * @internal
 */
final class Time
{
    private const MIN = -62135596800.0; // 0001-01-01T00:00:00Z
    private const MAX = 253402300799.0; // 9999-12-31T23:59:59Z

    /** The default clock: milliseconds since the Unix epoch. */
    public static function nowMs(): float
    {
        return microtime(true) * 1000;
    }

    /**
     * A UTC DateTimeImmutable for Unix seconds (fractions kept to the
     * microsecond). Values beyond the years 1 to 9999 are clamped: checks are
     * always made on the numeric value, this is only its representation.
     */
    public static function fromUnixSeconds(int|float $seconds): \DateTimeImmutable
    {
        $v = max(self::MIN, min(self::MAX, (float) $seconds));
        $sec = floor($v);
        $usec = (int) round(($v - $sec) * 1_000_000);
        if ($usec >= 1_000_000) {
            $sec += 1;
            $usec -= 1_000_000;
        }
        $dt = \DateTimeImmutable::createFromFormat('U.u', sprintf('%.0f.%06d', $sec, $usec), new \DateTimeZone('UTC'));
        if ($dt === false) {
            throw new \LogicException('time: unrepresentable timestamp');
        }
        return $dt->setTimezone(new \DateTimeZone('UTC'));
    }

    /** Milliseconds since the Unix epoch. */
    public static function toMs(\DateTimeInterface $t): float
    {
        return $t->getTimestamp() * 1000 + intdiv((int) $t->format('u'), 1000);
    }

    /**
     * Parses an RFC 3339 / ISO 8601 timestamp to milliseconds, or NAN when it
     * cannot be parsed (like JavaScript's Date.parse).
     */
    public static function parseMs(mixed $value): float
    {
        if (!is_string($value) || $value === '' || preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}/', $value) !== 1) {
            return NAN;
        }
        try {
            $dt = new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return NAN;
        }
        return self::toMs($dt);
    }
}

<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests\Support;

/**
 * A settable clock in milliseconds since the epoch.
 */
final class Clock
{
    public function __construct(public int|float $now)
    {
    }

    /** @return \Closure(): (int|float) */
    public function fn(): \Closure
    {
        return fn (): int|float => $this->now;
    }
}

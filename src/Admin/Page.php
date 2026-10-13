<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * One page of a cursor-paginated list (API-004).
 */
final class Page
{
    /**
     * @param list<mixed> $items
     */
    public function __construct(
        public readonly array $items,
        /** Empty on the last page. */
        public readonly string $nextCursor,
    ) {
    }
}

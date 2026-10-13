<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Introspection;

use ProudAuth\Sdk\Internal\Text;

/**
 * How operations are classified for support (impersonation) tokens (IMP-011,
 * IMP-012, IMP-013). The same rules as the Node and Go SDKs and the server's
 * decision API, pinned by sdk/fixtures/support-operations/cases.json:
 *
 *  - an operation name is trimmed, lowercased, "-" is read as "_", and the
 *    name is split into segments on ".", ":" and "/" (empty segments dropped);
 *  - it is protected when the segments of a protected entry occur anywhere in
 *    it as a contiguous run, with or without a trailing "s" on either side;
 *    an empty operation is protected (deny by default);
 *  - it is a write when any segment is a write verb, even when declared a read.
 */
final class SupportOperations
{
    /**
     * Operations that can never be performed with support access (IMP-012,
     * IMP-013). Class constants cannot be modified.
     */
    public const PROTECTED_OPERATIONS = [
        'password.change',
        'password.reset',
        'mfa.change',
        'identifier.change',
        'account.link',
        'credential.export',
        'api_key.create',
        'personal_token.create',
        'consent.modify',
        'idp.admin',
        'payment',
        'refund',
        'ownership.transfer',
        'secret.read',
        'secret',
        'delete',
        'purge',
    ];

    /**
     * Verbs that make an operation a write wherever they appear as a segment
     * of its name, even when the caller declared it a read ("orders.read.update"
     * is a write). Matching is exact per segment.
     */
    public const WRITE_SEGMENTS = [
        'create', 'add', 'insert', 'update', 'edit', 'modify', 'change', 'set', 'put', 'patch', 'write',
        'upsert', 'replace', 'delete', 'remove', 'destroy', 'erase', 'purge', 'archive', 'unarchive', 'restore', 'reset', 'rotate',
        'revoke', 'grant', 'assign', 'unassign', 'link', 'unlink', 'transfer', 'issue', 'approve', 'reject', 'cancel', 'enable',
        'disable', 'suspend', 'reactivate', 'activate', 'deactivate', 'lock', 'unlock', 'invite', 'send', 'submit', 'publish',
        'unpublish', 'import', 'merge', 'move', 'rename', 'refund', 'pay', 'execute',
    ];

    /**
     * Reports whether the operation touches a protected identity, money or
     * secret operation anywhere in its name under the given list (default
     * PROTECTED_OPERATIONS; a list passed here replaces the defaults, so pass
     * [...SupportOperations::PROTECTED_OPERATIONS, ...$yours] to extend them).
     *
     * @param list<string>|null $protectedOperations
     */
    public static function isProtectedOperation(string $operation, ?array $protectedOperations = null): bool
    {
        $segs = self::segments($operation);
        if ($segs === []) {
            return true;
        }
        foreach ($protectedOperations ?? self::PROTECTED_OPERATIONS as $p) {
            if (self::containsRun($segs, self::segments((string) $p))) {
                return true;
            }
        }
        return false;
    }

    /** Reports whether any segment of the operation is a write verb (WRITE_SEGMENTS). */
    public static function isWriteOperation(string $operation): bool
    {
        foreach (self::segments($operation) as $s) {
            if (in_array($s, self::WRITE_SEGMENTS, true)) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    private static function segments(string $operation): array
    {
        $norm = str_replace('-', '_', Text::lower(Text::trim($operation)));
        $parts = preg_split('#[.:/]#', $norm) ?: [];
        return array_values(array_filter($parts, static fn (string $s): bool => $s !== ''));
    }

    /** One operation segment matches one entry segment, tolerating a simple plural on either side. */
    private static function segmentMatches(string $seg, string $entry): bool
    {
        return $seg === $entry || $seg === $entry . 's' || $seg . 's' === $entry;
    }

    /**
     * Whether the entry's segments occur as a contiguous run in the operation's segments.
     *
     * @param list<string> $segs
     * @param list<string> $entry
     */
    private static function containsRun(array $segs, array $entry): bool
    {
        $n = count($entry);
        if ($n === 0 || $n > count($segs)) {
            return false;
        }
        for ($start = 0; $start + $n <= count($segs); $start++) {
            $all = true;
            for ($k = 0; $k < $n; $k++) {
                if (!self::segmentMatches($segs[$start + $k], $entry[$k])) {
                    $all = false;
                    break;
                }
            }
            if ($all) {
                return true;
            }
        }
        return false;
    }
}

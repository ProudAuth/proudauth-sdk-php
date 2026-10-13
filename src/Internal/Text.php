<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal;

/**
 * String helpers with JavaScript semantics, so classification and parsing
 * match the Node SDK character for character.
 *
 * @internal
 */
final class Text
{
    /** JavaScript's \s (WhiteSpace and LineTerminator). */
    private const JS_SPACE = '\x{0009}-\x{000D}\x{0020}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}';

    /** `s.split(/\s+/).filter(Boolean)` */
    public static function splitWhitespace(string $s): array
    {
        $parts = preg_split('/[' . self::JS_SPACE . ']+/u', $s);
        if ($parts === false) {
            $parts = preg_split('/[\t\n\v\f\r ]+/', $s) ?: [];
        }
        return array_values(array_filter($parts, static fn (string $p): bool => $p !== ''));
    }

    /** `s.trim()` */
    public static function trim(string $s): string
    {
        $t = preg_replace('/^[' . self::JS_SPACE . ']+|[' . self::JS_SPACE . ']+$/u', '', $s);
        return $t ?? trim($s, "\t\n\v\f\r ");
    }

    /**
     * `s.toLowerCase()`. Uses mbstring when available; without it, ASCII
     * letters are lowercased and the only non-ASCII letter whose lowercase
     * form is ASCII (U+212A KELVIN SIGN, "k") is mapped, so comparisons
     * against ASCII names are still exact.
     */
    public static function lower(string $s): string
    {
        if (function_exists('mb_strtolower') && preg_match('//u', $s) === 1) {
            return mb_strtolower($s, 'UTF-8');
        }
        return self::lowerWithoutMbstring($s);
    }

    /** The fallback of lower() when ext-mbstring is not loaded (public for tests). */
    public static function lowerWithoutMbstring(string $s): string
    {
        return str_replace("\u{212A}", 'k', strtolower($s));
    }
}

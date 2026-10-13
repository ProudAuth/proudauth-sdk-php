<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Internal\Json;

/**
 * Strict JSON parsing for security-sensitive inputs (JOSE headers, JWT
 * payloads, JWKS documents, introspection, discovery and token responses).
 *
 * json_decode() silently keeps the last of several members with the same
 * name, so two parties can read different values from one document. This
 * parser implements the complete RFC 8259 grammar itself and rejects
 * duplicate member names (compared after unescaping, so "iss" and "iss"
 * collide), invalid UTF-8, lone surrogates, nesting deeper than the limit and
 * trailing data. A byte order mark is not whitespace and is rejected.
 *
 * Objects are returned as JsonObject, arrays as PHP lists, numbers as int (when
 * they are integers that fit) or float, strings as UTF-8 strings.
 *
 * A port of sdk/node/src/internal/json.ts.
 *
 * @internal
 */
final class StrictJson
{
    /** Default nesting limit, matching the Go and Node SDKs. */
    public const DEFAULT_MAX_DEPTH = 32;

    private const NUMBER = '/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/';

    private const STOP = "\"\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        . "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

    private int $i = 0;
    private readonly int $n;

    private function __construct(private readonly string $text, private readonly int $maxDepth)
    {
        $this->n = strlen($text);
    }

    /**
     * Parses one JSON text.
     *
     * @throws StrictJsonException with reason "malformed" or "duplicate"
     */
    public static function decode(string $text, int $maxDepth = self::DEFAULT_MAX_DEPTH): mixed
    {
        if (preg_match('//u', $text) !== 1) {
            throw new StrictJsonException(StrictJsonException::MALFORMED);
        }
        $p = new self($text, $maxDepth);
        $v = $p->value(0);
        $p->whitespace();
        if ($p->i !== $p->n) {
            throw new StrictJsonException(StrictJsonException::MALFORMED);
        }
        return $v;
    }

    private static function fail(): never
    {
        throw new StrictJsonException(StrictJsonException::MALFORMED);
    }

    private function whitespace(): void
    {
        $this->i += strspn($this->text, " \t\n\r", $this->i);
    }

    private function peek(): string
    {
        return $this->i < $this->n ? $this->text[$this->i] : '';
    }

    private function value(int $depth): mixed
    {
        if ($depth > $this->maxDepth) {
            self::fail();
        }
        $this->whitespace();
        if ($this->i >= $this->n) {
            self::fail();
        }
        $c = $this->text[$this->i];
        switch ($c) {
            case '{':
                return $this->object($depth);
            case '[':
                return $this->array($depth);
            case '"':
                return $this->string();
            case 't':
                return $this->literal('true', true);
            case 'f':
                return $this->literal('false', false);
            case 'n':
                return $this->literal('null', null);
            default:
                return $this->number();
        }
    }

    private function literal(string $word, ?bool $value): ?bool
    {
        if (substr($this->text, $this->i, strlen($word)) !== $word) {
            self::fail();
        }
        $this->i += strlen($word);
        return $value;
    }

    private function object(int $depth): JsonObject
    {
        $this->i++; // {
        $members = [];
        $this->whitespace();
        if ($this->peek() === '}') {
            $this->i++;
            return new JsonObject($members);
        }
        for (;;) {
            $this->whitespace();
            if ($this->peek() !== '"') {
                self::fail();
            }
            $key = $this->string();
            if (array_key_exists($key, $members)) {
                throw new StrictJsonException(StrictJsonException::DUPLICATE);
            }
            $this->whitespace();
            if ($this->peek() !== ':') {
                self::fail();
            }
            $this->i++;
            $members[$key] = $this->value($depth + 1);
            $this->whitespace();
            $c = $this->peek();
            if ($c === ',') {
                $this->i++;
                continue;
            }
            if ($c === '}') {
                $this->i++;
                return new JsonObject($members);
            }
            self::fail();
        }
    }

    /** @return list<mixed> */
    private function array(int $depth): array
    {
        $this->i++; // [
        $items = [];
        $this->whitespace();
        if ($this->peek() === ']') {
            $this->i++;
            return $items;
        }
        for (;;) {
            $items[] = $this->value($depth + 1);
            $this->whitespace();
            $c = $this->peek();
            if ($c === ',') {
                $this->i++;
                continue;
            }
            if ($c === ']') {
                $this->i++;
                return $items;
            }
            self::fail();
        }
    }

    private function string(): string
    {
        $this->i++; // opening quote
        $out = '';
        for (;;) {
            $run = strcspn($this->text, self::STOP, $this->i);
            $out .= substr($this->text, $this->i, $run);
            $this->i += $run;
            if ($this->i >= $this->n) {
                self::fail();
            }
            $c = $this->text[$this->i];
            if ($c === '"') {
                $this->i++;
                return $out;
            }
            if ($c !== '\\') {
                self::fail(); // unescaped control character
            }
            $this->i++;
            if ($this->i >= $this->n) {
                self::fail();
            }
            $e = $this->text[$this->i];
            $this->i++;
            switch ($e) {
                case '"':
                    $out .= '"';
                    break;
                case '\\':
                    $out .= '\\';
                    break;
                case '/':
                    $out .= '/';
                    break;
                case 'b':
                    $out .= "\x08";
                    break;
                case 'f':
                    $out .= "\x0c";
                    break;
                case 'n':
                    $out .= "\n";
                    break;
                case 'r':
                    $out .= "\r";
                    break;
                case 't':
                    $out .= "\t";
                    break;
                case 'u':
                    $out .= $this->unicodeEscape();
                    break;
                default:
                    self::fail();
            }
        }
    }

    /** Decodes \uXXXX (the "\u" is consumed), pairing surrogates; lone surrogates are malformed. */
    private function unicodeEscape(): string
    {
        $cu = $this->hex4();
        if ($cu >= 0xDC00 && $cu <= 0xDFFF) {
            self::fail(); // lone low surrogate
        }
        if ($cu >= 0xD800 && $cu <= 0xDBFF) {
            if (substr($this->text, $this->i, 2) !== '\\u') {
                self::fail(); // lone high surrogate
            }
            $this->i += 2;
            $lo = $this->hex4();
            if ($lo < 0xDC00 || $lo > 0xDFFF) {
                self::fail();
            }
            $cu = 0x10000 + (($cu - 0xD800) << 10) + ($lo - 0xDC00);
        }
        return self::utf8($cu);
    }

    private function hex4(): int
    {
        $h = substr($this->text, $this->i, 4);
        if (strlen($h) !== 4 || strspn($h, '0123456789abcdefABCDEF') !== 4) {
            self::fail();
        }
        $this->i += 4;
        return (int) hexdec($h);
    }

    private static function utf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F))
            . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    private function number(): int|float
    {
        if (preg_match(self::NUMBER, $this->text, $m, 0, $this->i) !== 1 || $m[0] === '') {
            self::fail();
        }
        $s = $m[0];
        $this->i += strlen($s);
        if (strpbrk($s, '.eE') === false) {
            $int = (int) $s;
            if ((string) $int === $s) {
                return $int;
            }
        }
        return (float) $s;
    }
}

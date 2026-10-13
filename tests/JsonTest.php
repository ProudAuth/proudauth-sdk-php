<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Internal\Base64Url;
use ProudAuth\Sdk\Internal\Json\JsonObject;
use ProudAuth\Sdk\Internal\Json\StrictJson;
use ProudAuth\Sdk\Internal\Json\StrictJsonException;

final class JsonTest extends TestCase
{
    private static function reason(string $text): ?string
    {
        try {
            StrictJson::decode($text);
            return null;
        } catch (StrictJsonException $e) {
            return $e->reason;
        }
    }

    public function testParsesValidJsonLikeJsonDecode(): void
    {
        foreach (['{}', '[]', '{"a":[1,2,{"b":null}],"c":"\\u00e9\\n","d":-1.5e3,"e":true,"f":false}', ' "x" ', '0', '{"a":{"a":1}}', '{"x":"\\ud83d\\ude00","y":"\\/"}'] as $t) {
            self::assertSame(json_decode($t, true, 512, JSON_THROW_ON_ERROR), JsonObject::toPhp(StrictJson::decode($t)), $t);
        }
    }

    public function testKeepsObjectsApartFromArrays(): void
    {
        self::assertInstanceOf(JsonObject::class, StrictJson::decode('{}'));
        self::assertSame([], StrictJson::decode('[]'));
        $o = StrictJson::decode('{"0":"a","":"empty","\\u0000x":1}');
        self::assertInstanceOf(JsonObject::class, $o);
        self::assertSame('a', $o->get('0'));
        self::assertSame('empty', $o->get(''));
        self::assertSame(1, $o->get("\0x"));
        self::assertTrue($o->has('0'));
        $n = StrictJson::decode('{"a":null}');
        self::assertTrue($n->has('a'));
        self::assertFalse($n->has('b'));
    }

    public function testParsesNumbersAsIntOrFloat(): void
    {
        self::assertSame(1900000000, StrictJson::decode('1900000000'));
        self::assertSame(-12, StrictJson::decode('-12'));
        self::assertSame(1.5, StrictJson::decode('1.5'));
        self::assertSame(1000.0, StrictJson::decode('1e3'));
        self::assertSame(9.9999999999999999e19, StrictJson::decode('99999999999999999999'));
        self::assertSame(-0.0, StrictJson::decode('-0'));
        self::assertTrue(is_infinite(StrictJson::decode('1e400')));
    }

    public function testRejectsDuplicateMemberNamesIncludingEscapedOnes(): void
    {
        self::assertSame('duplicate', self::reason('{"a":1,"a":2}'));
        self::assertSame('duplicate', self::reason('{"iss":"x","\\u0069ss":"y"}'));
        self::assertSame('duplicate', self::reason('{"x":{"a":1,"a":1}}'));
        self::assertSame('duplicate', self::reason('[{"a":1,"a":1}]'));
        self::assertSame('duplicate', self::reason('{"1":1,"\\u0031":2}'));
        self::assertSame(null, self::reason('{"1":1,"01":2}'));
    }

    public function testRejectsTrailingDataInvalidGrammarLoneSurrogatesAndDeepNesting(): void
    {
        foreach ([
            '{} {}',
            '{}x',
            '{"a":1,}',
            '[1,]',
            "{'a':1}",
            '{"a":01}',
            '{"a":.5}',
            '{"a":NaN}',
            "{\"a\":\"\t\"}",
            '{"a":"\\x41"}',
            '{"a":"\\ud800"}',
            '{"a":"\\udc00"}',
            '{"a":"\\ud800\\u0041"}',
            '{"a":"\\ud800',
            "\u{FEFF}{}",
            '',
            '{"a":1',
            '{"a":tru}',
            '{"a":-}',
            '{"a":1e}',
            '{"a" 1}',
            "{\"a\":\"\xff\"}",
            "{\"a\":\"\xed\xa0\x80\"}",
            "{\"a\":\"\xc0\xaf\"}",
            str_repeat('[', 34) . str_repeat(']', 34),
        ] as $t) {
            self::assertSame('malformed', self::reason($t), var_export($t, true));
        }
        StrictJson::decode(str_repeat('[', 33) . str_repeat(']', 33));
        self::assertSame('malformed', self::reason(str_repeat('[', 33) . '1' . str_repeat(']', 33)));
    }

    public function testDecodesOnlyCanonicalUnpaddedBase64url(): void
    {
        self::assertSame('hi', Base64Url::decode('aGk'));
        self::assertSame('', Base64Url::decode(''));
        foreach (['aGk=', 'aG+k', 'aG/k', 'aGl', 'a', 'aG k', "aGk\n"] as $s) {
            self::assertThrows(\InvalidArgumentException::class, static fn () => Base64Url::decode($s), null, $s);
        }
    }
}

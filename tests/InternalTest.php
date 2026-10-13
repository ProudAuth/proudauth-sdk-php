<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Internal\HttpClient;
use ProudAuth\Sdk\Internal\Query;
use ProudAuth\Sdk\Internal\Time;
use ProudAuth\Sdk\Internal\Url;

/**
 * The strict URL parser, URLSearchParams-compatible query strings, form
 * encoding and time conversion.
 */
final class InternalTest extends TestCase
{
    public function testParsesAndNormalizesHttpUrls(): void
    {
        $u = Url::parse('HTTPS://ID.Example.COM:443/realms/main?a=1#f');
        self::assertSame('https://id.example.com', $u->origin());
        self::assertSame('https://id.example.com/realms/main?a=1#f', $u->toString());
        self::assertSame('http://127.0.0.1:8080/', Url::parse('http://127.0.0.1:8080')->toString());
        self::assertSame('http://[::1]:9/x', Url::parse('http://[::1]:9/x')->toString());
        self::assertSame('https://a.test/p?x', Url::parse('https://a.test/p?q=1')->withQuery('x')->toString());
        self::assertSame('https://a.test:8443', Url::parse('https://a.test:8443/')->origin());
    }

    public function testRefusesAmbiguousOrForeignUrls(): void
    {
        $reason = static function (string $s): string {
            try {
                Url::parse($s);
                return 'accepted';
            } catch (\UnexpectedValueException $e) {
                return $e->getMessage();
            }
        };
        foreach (["https://x.test/\n", 'https://x.test/ a', ' https://x.test/', 'https://x.test\\@evil.test/', 'https://x.test:99999/', 'https://[zz]/',
            'http:x.test', 'https://', 'https://:80/', 'https://x%2etest/', "https://x.test/\u{00e9}", 'not a url', ''] as $bad) {
            self::assertSame(Url::NOT_ABSOLUTE, $reason($bad), var_export($bad, true));
        }
        foreach (['file:///etc/passwd', 'ftp://x.test/', 'javascript:alert(1)', 'gopher://x.test'] as $bad) {
            self::assertSame(Url::NOT_HTTP, $reason($bad), $bad);
        }
        foreach (['https://user:pw@x.test/', 'https://user@x.test/', 'https://x.test@evil.test/'] as $bad) {
            self::assertSame(Url::CREDENTIALS, $reason($bad), $bad);
        }
        self::assertThrows(\InvalidArgumentException::class, static fn () => Url::requireHttp(null, 'endpoint', 'x'), static fn (\Throwable $e): bool => $e->getMessage() === 'x: endpoint is required');
    }

    public function testHandlesQueryStringsLikeUrlSearchParams(): void
    {
        $q = Query::parse('?a=1&b=x+y&a=2&c&=e&&d=%2B%zz&access%5Ftoken=t');
        self::assertSame(['1', '2'], $q->getAll('a'));
        self::assertSame(['x y'], $q->getAll('b'));
        self::assertSame([''], $q->getAll('c'));
        self::assertSame(['e'], $q->getAll(''));
        self::assertSame(['+%zz'], $q->getAll('d'));
        self::assertTrue($q->has('access_token'));
        $q->set('a', '3');
        $q->set('new', 'a b*~é');
        self::assertSame('a=3&b=x+y&c=&=e&d=%2B%25zz&access_token=t&new=a+b*%7E%C3%A9', $q->toString());
        self::assertSame('a=1&a=2&b=true', Query::fromArray(['a' => ['1', '2'], 'b' => true])->toString());
    }

    public function testEncodesFormsLikeGoQueryEscapeAndUrisLikeJavascript(): void
    {
        self::assertSame('orders-api%3Ars', HttpClient::formEncode('orders-api:rs'));
        self::assertSame('a+b~%2A%21', HttpClient::formEncode('a b~*!'));
        self::assertSame('token=a.b%2Bc&x=%26', HttpClient::formBody(['token' => 'a.b+c', 'skip' => null, 'x' => '&']));
        self::assertSame('main%20realm%2F!*()\'~', HttpClient::encodeUriComponent("main realm/!*()'~"));
    }

    public function testConvertsTimesWithoutLosingPrecisionOrFailingOnExtremes(): void
    {
        self::assertSame('2027-01-15T08:00:00.500000+00:00', Time::fromUnixSeconds(1800000000.5)->format('Y-m-d\TH:i:s.uP'));
        self::assertSame('9999-12-31', Time::fromUnixSeconds(1e20)->format('Y-m-d'));
        self::assertSame('0001-01-01', Time::fromUnixSeconds(-1e20)->format('Y-m-d'));
        self::assertSame(1800000000500.0, Time::toMs(Time::fromUnixSeconds(1800000000.5)));
        self::assertSame(1791626400123.0, Time::parseMs('2026-10-10T10:00:00.123Z'));
        self::assertSame(1791626400000.0, Time::parseMs('2026-10-10T12:00:00+02:00'));
        self::assertTrue(is_nan(Time::parseMs('garbage')));
        self::assertTrue(is_nan(Time::parseMs(null)));
        self::assertTrue(is_nan(Time::parseMs('2026-13-45T99:00:00Z')));
    }
}

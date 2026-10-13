<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Oidc\OidcErrorCode;
use ProudAuth\Sdk\Oidc\OidcException;
use ProudAuth\Sdk\Verifier\VerifierErrorCode;
use ProudAuth\Sdk\Verifier\VerifierException;

/**
 * A minimal xUnit-style base class (no PHPUnit: the tests must run without
 * Composer). Public methods whose names start with "test" are tests; each runs
 * on a fresh instance after setUp().
 */
abstract class TestCase
{
    public static int $assertions = 0;

    public static function setUpBeforeClass(): void
    {
    }

    public static function tearDownAfterClass(): void
    {
    }

    protected function setUp(): void
    {
    }

    protected function tearDown(): void
    {
    }

    /** @internal used by the runner */
    final public function runTest(string $method): void
    {
        $this->setUp();
        try {
            $this->{$method}();
        } finally {
            $this->tearDown();
        }
    }

    protected static function fail(string $message): never
    {
        throw new AssertionFailed($message);
    }

    protected static function assertTrue(mixed $actual, string $message = ''): void
    {
        self::$assertions++;
        if ($actual !== true) {
            self::fail(($message !== '' ? $message . ': ' : '') . 'expected true, got ' . self::export($actual));
        }
    }

    protected static function assertFalse(mixed $actual, string $message = ''): void
    {
        self::$assertions++;
        if ($actual !== false) {
            self::fail(($message !== '' ? $message . ': ' : '') . 'expected false, got ' . self::export($actual));
        }
    }

    protected static function assertSame(mixed $expected, mixed $actual, string $message = ''): void
    {
        self::$assertions++;
        if ($expected !== $actual) {
            self::fail(($message !== '' ? $message . ': ' : '') . 'expected ' . self::export($expected) . ', got ' . self::export($actual));
        }
    }

    protected static function assertNotSame(mixed $expected, mixed $actual, string $message = ''): void
    {
        self::$assertions++;
        if ($expected === $actual) {
            self::fail(($message !== '' ? $message . ': ' : '') . 'did not expect ' . self::export($actual));
        }
    }

    protected static function assertNull(mixed $actual, string $message = ''): void
    {
        self::assertSame(null, $actual, $message);
    }

    protected static function assertCount(int $expected, array $actual, string $message = ''): void
    {
        self::assertSame($expected, count($actual), $message);
    }

    protected static function assertInstanceOf(string $class, mixed $actual, string $message = ''): void
    {
        self::$assertions++;
        if (!$actual instanceof $class) {
            self::fail(($message !== '' ? $message . ': ' : '') . "expected an instance of {$class}, got " . get_debug_type($actual));
        }
    }

    protected static function assertStringContains(string $needle, string $haystack, string $message = ''): void
    {
        self::$assertions++;
        if (!str_contains($haystack, $needle)) {
            self::fail(($message !== '' ? $message . ': ' : '') . self::export($haystack) . ' does not contain ' . self::export($needle));
        }
    }

    protected static function assertStringNotContains(string $needle, string $haystack, string $message = ''): void
    {
        self::$assertions++;
        if ($needle !== '' && str_contains($haystack, $needle)) {
            self::fail(($message !== '' ? $message . ': ' : '') . 'unexpectedly contains ' . self::export($needle));
        }
    }

    protected static function assertMatches(string $pattern, string $actual, string $message = ''): void
    {
        self::$assertions++;
        if (preg_match($pattern, $actual) !== 1) {
            self::fail(($message !== '' ? $message . ': ' : '') . self::export($actual) . " does not match {$pattern}");
        }
    }

    /**
     * Asserts that $fn throws an instance of $class (and that $check, if given,
     * accepts it). Returns the exception.
     *
     * @template T of \Throwable
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    protected static function assertThrows(string $class, \Closure $fn, ?\Closure $check = null, string $message = ''): \Throwable
    {
        self::$assertions++;
        try {
            $fn();
        } catch (\Throwable $e) {
            if (!$e instanceof $class) {
                self::fail(($message !== '' ? $message . ': ' : '') . "expected {$class}, got " . get_class($e) . ': ' . $e->getMessage());
            }
            if ($check !== null && $check($e) === false) {
                self::fail(($message !== '' ? $message . ': ' : '') . 'exception did not match: ' . get_class($e) . ': ' . $e->getMessage());
            }
            return $e;
        }
        self::fail(($message !== '' ? $message . ': ' : '') . "expected {$class}, nothing was thrown");
    }

    /** Asserts a VerifierException of the given category. */
    protected static function assertVerifierError(VerifierErrorCode $code, \Closure $fn, string $message = ''): VerifierException
    {
        $e = self::assertThrows(VerifierException::class, $fn, null, $message);
        self::assertSame($code, $e->errorCode, ($message !== '' ? $message . ': ' : '') . 'category (' . $e->getMessage() . ')');
        return $e;
    }

    /** Asserts an OidcException of the given category (and reason, when given). */
    protected static function assertOidcError(OidcErrorCode $code, \Closure $fn, ?string $reason = null, string $message = ''): OidcException
    {
        $e = self::assertThrows(OidcException::class, $fn, null, $message);
        self::assertSame($code, $e->errorCode, ($message !== '' ? $message . ': ' : '') . $e->getMessage());
        if ($reason !== null) {
            self::assertSame($reason, $e->reason, ($message !== '' ? $message . ': ' : '') . $e->getMessage());
        }
        return $e;
    }

    protected static function export(mixed $v): string
    {
        if ($v instanceof \UnitEnum) {
            return get_class($v) . '::' . $v->name;
        }
        if (is_object($v)) {
            return get_class($v);
        }
        $s = var_export($v, true);
        $s = preg_replace('/\s+/', ' ', $s) ?? $s;
        return strlen($s) > 300 ? substr($s, 0, 300) . '...' : $s;
    }
}

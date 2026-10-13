<?php

declare(strict_types=1);

/*
 * Self-contained test runner (no PHPUnit, no Composer).
 *
 *     php tests/run.php                 # every test
 *     php tests/run.php Verifier        # test classes or methods containing "Verifier"
 *
 * Every PHP warning, notice and deprecation fails the test that raised it.
 * Exits with status 1 when any test fails.
 */

error_reporting(-1);
ini_set('display_errors', '1');
ini_set('assert.exception', '1');

set_error_handler(static function (int $errno, string $message, string $file, int $line): bool {
    if ((error_reporting() & $errno) === 0) {
        return false; // silenced with @
    }
    throw new ErrorException($message, 0, $errno, $file, $line);
});

require __DIR__ . '/bootstrap.php';

use ProudAuth\Sdk\Tests\AssertionFailed;
use ProudAuth\Sdk\Tests\TestCase;

$filter = $argv[1] ?? '';
$files = glob(__DIR__ . '/*Test.php') ?: [];
sort($files);

$started = microtime(true);
$passed = 0;
$failed = [];
$total = 0;

printf("ProudAuth PHP SDK tests (PHP %s, %s, libsodium %s)\n", PHP_VERSION, OPENSSL_VERSION_TEXT, SODIUM_LIBRARY_VERSION);

foreach ($files as $file) {
    $class = 'ProudAuth\\Sdk\\Tests\\' . basename($file, '.php');
    $ref = new ReflectionClass($class);
    if ($ref->isAbstract() || !$ref->isSubclassOf(TestCase::class)) {
        continue;
    }
    $methods = [];
    foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
        if (str_starts_with($m->getName(), 'test') && !$m->isStatic()) {
            if ($filter === '' || stripos($ref->getShortName() . '::' . $m->getName(), $filter) !== false) {
                $methods[] = $m->getName();
            }
        }
    }
    if ($methods === []) {
        continue;
    }
    echo "\n", $ref->getShortName(), "\n";
    try {
        $class::setUpBeforeClass();
    } catch (Throwable $e) {
        foreach ($methods as $method) {
            $total++;
            $failed[] = "{$ref->getShortName()}::{$method}";
            printf("  FAIL  %s\n        setUpBeforeClass: %s: %s\n", $method, get_class($e), $e->getMessage());
        }
        continue;
    }
    foreach ($methods as $method) {
        $total++;
        $label = strtolower(trim(preg_replace('/(?<!^)[A-Z]/', ' $0', substr($method, 4)) ?? $method));
        $t0 = microtime(true);
        try {
            (new $class())->runTest($method);
            $passed++;
            $ms = (microtime(true) - $t0) * 1000;
            printf("  ok    %s%s\n", $label, $ms >= 500 ? sprintf(' (%d ms)', $ms) : '');
        } catch (Throwable $e) {
            $failed[] = "{$ref->getShortName()}::{$method}";
            $where = $e instanceof AssertionFailed ? self_location($e) : $e->getFile() . ':' . $e->getLine();
            printf(
                "  FAIL  %s\n        %s%s\n        at %s\n",
                $label,
                $e instanceof AssertionFailed ? '' : get_class($e) . ': ',
                $e->getMessage(),
                $where,
            );
        }
    }
    try {
        $class::tearDownAfterClass();
    } catch (Throwable $e) {
        printf("  WARN  tearDownAfterClass: %s\n", $e->getMessage());
    }
}

/** The first frame of an assertion failure that is inside a test file. */
function self_location(Throwable $e): string
{
    foreach ($e->getTrace() as $frame) {
        $file = $frame['file'] ?? '';
        if ($file !== '' && str_ends_with($file, 'Test.php')) {
            return $file . ':' . ($frame['line'] ?? 0);
        }
    }
    return $e->getFile() . ':' . $e->getLine();
}

printf(
    "\n%d tests, %d assertions: %d passed, %d failed (%.2f s)\n",
    $total,
    TestCase::$assertions,
    $passed,
    count($failed),
    microtime(true) - $started,
);
if ($failed !== []) {
    echo "\nFailed:\n";
    foreach ($failed as $f) {
        echo "  - {$f}\n";
    }
    exit(1);
}
exit($total === 0 ? 1 : 0);

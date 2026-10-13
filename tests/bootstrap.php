<?php

declare(strict_types=1);

/*
 * PSR-4 autoloading for the SDK and its tests without Composer. Applications
 * installing the package through Composer use its autoloader instead.
 */
spl_autoload_register(static function (string $class): void {
    $prefixes = [
        'ProudAuth\\Sdk\\Tests\\' => __DIR__ . '/',
        'ProudAuth\\Sdk\\' => dirname(__DIR__) . '/src/',
    ];
    foreach ($prefixes as $prefix => $dir) {
        if (str_starts_with($class, $prefix)) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
});

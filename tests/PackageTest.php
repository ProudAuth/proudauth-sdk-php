<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests;

use ProudAuth\Sdk\Version;

/**
 * The package as Composer consumers see it (the counterpart of
 * sdk/node/test/exports.test.ts).
 */
final class PackageTest extends TestCase
{
    private const ROOT = __DIR__ . '/..';

    public function testComposerMetadataDeclaresNoPackageDependencies(): void
    {
        $c = json_decode((string) file_get_contents(self::ROOT . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('proudauth/sdk', $c['name']);
        self::assertSame('0.2.0', $c['version']);
        self::assertSame(Version::SDK_VERSION, $c['version']);
        self::assertSame('Apache-2.0', $c['license']);
        self::assertSame(['ProudAuth\\Sdk\\' => 'src/'], $c['autoload']['psr-4']);
        self::assertSame(['php', 'ext-curl', 'ext-json', 'ext-openssl', 'ext-sodium'], array_keys($c['require']));
        self::assertSame('>=8.2', $c['require']['php']);
        self::assertTrue(!isset($c['require-dev']), 'no development packages either');
    }

    public function testShipsTheApacheLicense(): void
    {
        self::assertSame('cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30', hash_file('sha256', self::ROOT . '/LICENSE'));
        self::assertStringContains('Apache License', (string) file_get_contents(self::ROOT . '/LICENSE'));
    }

    public function testEverySourceFileFollowsPsr4AndStrictTypes(): void
    {
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::ROOT . '/src', \FilesystemIterator::SKIP_DOTS));
        $count = 0;
        foreach ($files as $f) {
            $path = $f->getPathname();
            $src = (string) file_get_contents($path);
            self::assertStringContains('declare(strict_types=1);', $src, $path);
            $class = 'ProudAuth\\Sdk\\' . str_replace('/', '\\', substr($path, strlen(self::ROOT . '/src/'), -4));
            self::assertTrue(class_exists($class) || interface_exists($class) || enum_exists($class), "{$class} autoloads from {$path}");
            $count++;
        }
        self::assertTrue($count > 40);
    }

    public function testExposesThePublicEntryPoints(): void
    {
        foreach ([
            'Verifier\\Verifier', 'Verifier\\Claims', 'Verifier\\Actor', 'Verifier\\VerifierException', 'Verifier\\VerifierErrorCode',
            'Verifier\\MultiIssuerVerifier', 'Verifier\\IssuerRegistration', 'Verifier\\TenantClaims', 'Verifier\\Authenticator',
            'Middleware\\BearerToken', 'Middleware\\Challenge', 'Middleware\\RequestAuthenticator',
            'Introspection\\Introspector', 'Introspection\\SupportGuard', 'Introspection\\SupportEvent', 'Introspection\\SupportAuditor',
            'Introspection\\SupportOperations', 'Introspection\\RouteAuthenticator',
            'BoundedState\\BoundedState', 'BoundedState\\BoundedVerifier', 'BoundedState\\CursorExpiredException',
            'Oidc\\OidcClient', 'Oidc\\Session', 'Oidc\\AuthRequest', 'Oidc\\TokenSet', 'Oidc\\IdTokenClaims', 'Oidc\\CodeExchangeResult',
            'Oidc\\OidcException', 'Oidc\\OidcErrorCode', 'Oidc\\Pkce', 'Oidc\\FileRefreshLock',
            'Admin\\AdminClient', 'Admin\\AdminResponse', 'Admin\\Page', 'Admin\\RequestOptions', 'Admin\\Secret',
            'Admin\\ProblemException', 'Admin\\AdminRequestException', 'Admin\\AdminErrorCode',
            'Http\\Transport', 'Http\\CurlTransport', 'Http\\Request', 'Http\\Response', 'Http\\TransportException',
            'Cache\\Store', 'Cache\\MemoryStore', 'Cache\\FileStore', 'Version',
        ] as $name) {
            $fq = 'ProudAuth\\Sdk\\' . $name;
            self::assertTrue(class_exists($fq) || interface_exists($fq) || enum_exists($fq), $fq);
        }
        // Introspection and bounded state share the verifier's error class, like the Node entry points.
        self::assertTrue(is_subclass_of(\ProudAuth\Sdk\BoundedState\CursorExpiredException::class, \ProudAuth\Sdk\Verifier\VerifierException::class));
        self::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA'], \ProudAuth\Sdk\Verifier\Verifier::SUPPORTED_ALGORITHMS);
    }
}

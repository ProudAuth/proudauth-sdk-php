<?php

declare(strict_types=1);

namespace ProudAuth\Sdk;

/**
 * The SDK version, sent by the administration client with every request
 * ("ProudAuth-SDK: php/0.2.0").
 */
final class Version
{
    public const SDK_VERSION = '0.2.0';

    private function __construct()
    {
    }
}

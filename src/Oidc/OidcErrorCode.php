<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * OIDC client error categories, identical to the Node SDK's OIDCErrorCode.
 */
enum OidcErrorCode: string
{
    case State = 'state';
    case IdToken = 'id_token';
    case Nonce = 'nonce';
    case Reauthenticate = 'reauthenticate';
    case Provider = 'provider';
    case Configuration = 'configuration';

    public function message(): string
    {
        return match ($this) {
            self::State => 'state mismatch',
            self::IdToken => 'invalid ID token',
            self::Nonce => 'nonce mismatch',
            self::Reauthenticate => 'refresh failed; the user must authenticate again',
            self::Provider => 'provider error',
            self::Configuration => 'invalid configuration',
        };
    }
}

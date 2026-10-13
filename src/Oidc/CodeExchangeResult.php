<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Oidc;

/**
 * The result of OidcClient::exchangeCode().
 */
final class CodeExchangeResult
{
    public function __construct(
        public readonly TokenSet $tokens,
        /** The validated ID-token claims; null only when "openid" was not requested. */
        public readonly ?IdTokenClaims $idClaims,
    ) {
    }
}

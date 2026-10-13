<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * Transport-level failure categories of the administration client (the Node
 * SDK's AdminErrorCode without "aborted": PHP requests cannot be cancelled
 * from outside).
 */
enum AdminErrorCode: string
{
    case Timeout = 'timeout';
    case Network = 'network';
    case InvalidResponse = 'invalid_response';
    case TokenSource = 'token_source';
}

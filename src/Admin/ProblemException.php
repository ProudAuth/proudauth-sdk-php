<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * An RFC 9457 problem returned by the API (API-007). getCode() returns the
 * HTTP status.
 */
final class ProblemException extends \RuntimeException
{
    /** Stable machine-readable code (the problem's "code", else the status text). */
    public readonly string $errorCode;
    public readonly string $title;
    public readonly string $detail;
    public readonly ?string $type;
    public readonly ?string $instance;
    /** @var array<string, string> field-level validation errors */
    public readonly array $errors;
    public readonly string $requestId;
    /** @var array<string, mixed> every member of the problem document, for extension members */
    public readonly array $extra;

    /**
     * @param array<string, mixed>        $body
     * @param array<string, list<string>> $headers response headers (lowercase names), e.g. retry-after on 429
     */
    public function __construct(
        public readonly int $status,
        array $body,
        public readonly array $headers,
    ) {
        $s = static fn (string $k): string => isset($body[$k]) && is_string($body[$k]) ? $body[$k] : '';
        $code = $s('code');
        if ($code === '') {
            $code = HttpStatus::text($status) ?? "HTTP {$status}";
        }
        $title = $s('title');
        $detail = $s('detail');
        $errors = [];
        if (isset($body['errors']) && is_array($body['errors'])) {
            foreach ($body['errors'] as $k => $v) {
                if (is_string($v)) {
                    $errors[(string) $k] = $v;
                }
            }
        }
        $msg = "{$status} {$code}: {$title}";
        if ($detail !== '') {
            $msg .= " ({$detail})";
        }
        foreach ($errors as $k => $v) {
            $msg .= " [{$k}: {$v}]";
        }
        parent::__construct($msg, $status);
        $this->errorCode = $code;
        $this->title = $title;
        $this->detail = $detail;
        $this->type = $s('type') !== '' ? $s('type') : null;
        $this->instance = $s('instance') !== '' ? $s('instance') : null;
        $this->errors = $errors;
        $requestId = $s('request_id');
        if ($requestId === '') {
            $requestId = isset($headers['x-request-id']) ? implode(', ', $headers['x-request-id']) : '';
        }
        $this->requestId = $requestId;
        $this->extra = $body;
    }

    /** All values of a response header joined with ", ", or null. */
    public function header(string $name): ?string
    {
        $v = $this->headers[strtolower($name)] ?? null;
        return $v === null ? null : implode(', ', $v);
    }
}

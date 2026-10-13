<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Admin;

/**
 * A one-time secret returned by the API: a client secret, API key, webhook
 * signing secret, setup or handoff code, download token or recovery code
 * (SDK-007, SDK-008). It never prints, logs or serializes its value: string
 * conversion, json_encode(), var_dump(), print_r() and var_export() show
 * "[REDACTED]" or nothing, and serialize() refuses. reveal() returns the
 * value for the one place that must store it.
 *
 * The value is kept outside the object's properties, so casts to array and
 * reflection on the object do not expose it either.
 */
final class Secret implements \JsonSerializable, \Stringable
{
    /** @var \WeakMap<Secret, string>|null */
    private static ?\WeakMap $values = null;

    public function __construct(string $value)
    {
        self::$values ??= new \WeakMap();
        self::$values[$this] = $value;
    }

    /** The secret value. Call it only where the value must be stored or used. */
    public function reveal(): string
    {
        return self::$values[$this] ?? '';
    }

    public function __toString(): string
    {
        return $this->reveal() !== '' ? '[REDACTED]' : '';
    }

    public function jsonSerialize(): string
    {
        return $this->__toString();
    }

    public function __debugInfo(): array
    {
        return ['value' => $this->__toString()];
    }

    /** Secrets are immutable values; there is nothing to clone. */
    private function __clone()
    {
    }

    /** @return never */
    public function __serialize(): array
    {
        throw new \LogicException('admin: a Secret cannot be serialized; store reveal() explicitly where it belongs');
    }

    /** @param array<mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('admin: a Secret cannot be unserialized');
    }
}

<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Storage;

use DateTimeImmutable;

final readonly class AuthenticationTimeStore
{
    private FileState $state;

    public function __construct(string $path)
    {
        $this->state = new FileState($path);
    }

    public function recordSuccessfulLogin(): void
    {
        $this->state->update(
            /** @param array<string, mixed> $state */
            static function (array &$state): void {
                $state['authenticated_at'] = time();
            },
        );
    }

    public function current(): ?DateTimeImmutable
    {
        $timestamp = $this->state->read()['authenticated_at'] ?? null;
        if (!is_int($timestamp) || $timestamp <= 0) {
            return null;
        }

        return (new DateTimeImmutable())->setTimestamp($timestamp);
    }
}

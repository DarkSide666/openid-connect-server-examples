<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Storage;

final readonly class RevocationStore
{
    private FileState $state;

    public function __construct(string $path)
    {
        $this->state = new FileState($path);
    }

    public function revoke(string $identifier): void
    {
        $this->state->update(
            /** @param array<string, mixed> $items */
            static function (array &$items) use ($identifier): void {
                $items[$identifier] = true;
            },
        );
    }

    public function isRevoked(string $identifier): bool
    {
        return ($this->state->read()[$identifier] ?? false) === true;
    }
}

<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Storage;

use DateTimeImmutable;
use LogicException;
use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadata;
use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadataStoreInterface;

final readonly class FileAuthorizationCodeMetadataStore implements AuthorizationCodeMetadataStoreInterface
{
    private FileState $state;

    public function __construct(string $path)
    {
        $this->state = new FileState($path);
    }

    public function store(string $authorizationCodeId, AuthorizationCodeMetadata $metadata): void
    {
        $this->state->update(
            /** @param array<string, mixed> $items */
            static function (array &$items) use ($authorizationCodeId, $metadata): void {
                if (isset($items[$authorizationCodeId])) {
                    throw new LogicException('Duplicate authorization-code metadata.');
                }
                $items[$authorizationCodeId] = [
                    'nonce' => $metadata->nonce,
                    'expires_at' => $metadata->expiresAt->getTimestamp(),
                    'max_age' => $metadata->maxAge,
                    'session_id' => $metadata->sessionId,
                ];
            },
        );
    }

    public function consume(string $authorizationCodeId): ?AuthorizationCodeMetadata
    {
        return $this->state->update(
            /** @param array<string, mixed> $items */
            static function (array &$items) use ($authorizationCodeId): ?AuthorizationCodeMetadata {
                $record = $items[$authorizationCodeId] ?? null;
                unset($items[$authorizationCodeId]);
                if (!is_array($record) || !isset($record['nonce'], $record['expires_at']) || !is_string($record['nonce']) || !is_int($record['expires_at'])) {
                    return null;
                }
                $expiresAt = (new DateTimeImmutable())->setTimestamp($record['expires_at']);
                if ($expiresAt <= new DateTimeImmutable()) {
                    return null;
                }
                $maxAge = $record['max_age'] ?? null;
                $sessionId = $record['session_id'] ?? null;

                return new AuthorizationCodeMetadata(
                    $record['nonce'],
                    $expiresAt,
                    is_int($maxAge) ? $maxAge : null,
                    is_string($sessionId) ? $sessionId : null,
                );
            },
        );
    }
}

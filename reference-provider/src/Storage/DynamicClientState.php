<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Storage;

use DarkSide\OpenIdConnectServer\Registration\ClientRegistrationStoreInterface;
use DarkSide\OpenIdConnectServer\Registration\RegisteredClient;
use LogicException;

final readonly class DynamicClientState implements ClientRegistrationStoreInterface
{
    private FileState $state;

    public function __construct(string $path)
    {
        $this->state = new FileState($path);
    }

    public function create(RegisteredClient $client): void
    {
        $this->state->update(static function (array &$state) use ($client): void {
            $clients = $state['clients'] ?? [];
            if (!is_array($clients) || isset($clients[$client->clientId])) {
                throw new LogicException('Dynamic client identifier already exists.');
            }
            $metadata = $client->metadata;
            $metadata['client_secret_hash'] = $client->clientSecret !== null
                ? password_hash($client->clientSecret, PASSWORD_DEFAULT)
                : null;
            $clients[$client->clientId] = $metadata;
            $state['clients'] = $clients;
        });
    }

    /** @return array<string, mixed>|null */
    public function get(string $clientId): ?array
    {
        $clients = $this->state->read()['clients'] ?? [];
        $client = is_array($clients) ? ($clients[$clientId] ?? null) : null;
        return is_array($client) ? $client : null;
    }

    public function validatesSecret(string $clientId, string $secret): bool
    {
        $client = $this->get($clientId);
        $hash = $client['client_secret_hash'] ?? null;
        return is_string($hash) && password_verify($secret, $hash);
    }
}

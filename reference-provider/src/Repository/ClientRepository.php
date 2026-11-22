<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use DarkSide\OidcReferenceProvider\Entity\Client;

final readonly class ClientRepository implements ClientRepositoryInterface
{
    private Client $client;

    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
    ) {
        $this->client = new Client($clientId, 'OIDC Reference Test Client', $redirectUri, true);
        $this->clientSecret = $clientSecret;
    }

    private string $clientSecret;

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return hash_equals($this->client->getIdentifier(), $clientIdentifier) ? $this->client : null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return $clientSecret !== null
            && hash_equals($this->client->getIdentifier(), $clientIdentifier)
            && hash_equals($this->clientSecret, $clientSecret)
            && $grantType === 'authorization_code';
    }
}

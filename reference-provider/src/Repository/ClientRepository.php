<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use DarkSide\OidcReferenceProvider\Entity\Client;
use DarkSide\OidcReferenceProvider\Storage\DynamicClientState;

final readonly class ClientRepository implements ClientRepositoryInterface
{
    private Client $client;

    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        private ?DynamicClientState $dynamicClients = null,
    ) {
        $this->client = new Client($clientId, 'OIDC Reference Test Client', $redirectUri, true);
        $this->clientSecret = $clientSecret;
    }

    private string $clientSecret;

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        if (hash_equals($this->client->getIdentifier(), $clientIdentifier)) {
            return $this->client;
        }
        $metadata = $this->dynamicClients?->get($clientIdentifier);
        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris)) {
            return null;
        }
        $redirects = array_values(array_filter($redirectUris, 'is_string'));
        if ($redirects === []) {
            return null;
        }
        $grants = $metadata['grant_types'] ?? ['authorization_code'];
        return new Client(
            $clientIdentifier,
            is_string($metadata['client_name'] ?? null) ? $metadata['client_name'] : 'Dynamic OIDC Client',
            $redirects[0],
            ($metadata['token_endpoint_auth_method'] ?? 'client_secret_basic') !== 'none',
            is_array($grants) ? array_values(array_filter($grants, 'is_string')) : ['authorization_code'],
        );
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        if (hash_equals($this->client->getIdentifier(), $clientIdentifier)) {
            return $clientSecret !== null && hash_equals($this->clientSecret, $clientSecret)
                && in_array($grantType, ['authorization_code', 'refresh_token'], true);
        }
        $client = $this->getClientEntity($clientIdentifier);
        $metadata = $this->dynamicClients?->get($clientIdentifier);
        return $client instanceof Client && $clientSecret !== null
            && ($metadata['token_endpoint_auth_method'] ?? null) === 'client_secret_basic'
            && $this->dynamicClients?->validatesSecret($clientIdentifier, $clientSecret) === true
            && $client->supportsGrantType((string) $grantType);
    }
}

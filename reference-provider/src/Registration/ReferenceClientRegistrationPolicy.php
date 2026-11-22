<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Registration;

use DarkSide\OpenIdConnectServer\Registration\ClientRegistrationPolicyInterface;

final readonly class ReferenceClientRegistrationPolicy implements ClientRegistrationPolicyInterface
{
    public function __construct(private string $initialAccessToken)
    {
    }

    public function allows(array $metadata, ?string $initialAccessToken): bool
    {
        return $this->initialAccessToken !== '' && is_string($initialAccessToken)
            && hash_equals($this->initialAccessToken, $initialAccessToken)
            && ($metadata['application_type'] ?? 'web') === 'web'
            && is_array($metadata['redirect_uris'] ?? null) && count($metadata['redirect_uris']) === 1
            && (!isset($metadata['grant_types']) || $metadata['grant_types'] === ['authorization_code'])
            && (!isset($metadata['response_types']) || $metadata['response_types'] === ['code'])
            && (!isset($metadata['token_endpoint_auth_method']) || $metadata['token_endpoint_auth_method'] === 'client_secret_basic')
            && !isset($metadata['backchannel_logout_uri']);
    }

    public function provision(array $metadata, string $clientId): array
    {
        return $metadata + [
            'client_name' => 'Dynamic test client',
            'application_type' => 'web',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ];
    }
}

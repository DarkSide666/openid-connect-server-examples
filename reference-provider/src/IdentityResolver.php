<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider;

use DarkSide\OpenIdConnectServer\Identity\ArrayIdentity;
use DarkSide\OpenIdConnectServer\Identity\IdentityInterface;
use DarkSide\OpenIdConnectServer\Identity\IdentityResolverInterface;
use DarkSide\OidcReferenceProvider\Storage\AuthenticationTimeStore;

final readonly class IdentityResolver implements IdentityResolverInterface
{
    public function __construct(private AuthenticationTimeStore $authenticationTimeStore)
    {
    }

    /** @param list<string> $grantedScopes */
    public function resolve(string $userIdentifier, string $clientId, array $grantedScopes): IdentityInterface
    {
        if ($userIdentifier !== 'reference-user-001') {
            throw new \InvalidArgumentException('Unknown reference-provider user.');
        }
        $claims = [];
        if (in_array('profile', $grantedScopes, true)) {
            $claims['name'] = 'Reference Test User';
            $claims['preferred_username'] = 'alice';
        }
        if (in_array('email', $grantedScopes, true)) {
            $claims['email'] = 'alice@example.test';
            $claims['email_verified'] = true;
        }

        return new ArrayIdentity(
            'reference-user-subject-001',
            $claims,
            $this->authenticationTimeStore->current(),
        );
    }
}

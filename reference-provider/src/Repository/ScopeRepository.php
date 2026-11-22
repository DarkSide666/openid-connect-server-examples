<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use DarkSide\OidcReferenceProvider\Entity\Scope;

final readonly class ScopeRepository implements ScopeRepositoryInterface
{
    /** @var array<string, ScopeEntityInterface> */
    private array $scopes;

    public function __construct()
    {
        $scopes = [];
        foreach (['openid', 'profile', 'email', 'offline_access'] as $identifier) {
            $scopes[$identifier] = new Scope($identifier);
        }

        $this->scopes = $scopes;
    }

    public function getScopeEntityByIdentifier(?string $scopeIdentifier): ?ScopeEntityInterface
    {
        return $scopeIdentifier === null ? null : ($this->scopes[$scopeIdentifier] ?? null);
    }

    /** @param list<ScopeEntityInterface> $scopes @return list<ScopeEntityInterface> */
    public function finalizeScopes(
        array $scopes,
        string $grantTypeId,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        return $scopes;
    }
}

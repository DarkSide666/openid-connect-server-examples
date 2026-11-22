<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use InvalidArgumentException;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use DarkSide\OidcReferenceProvider\Entity\AccessToken;
use DarkSide\OidcReferenceProvider\Storage\RevocationStore;

final readonly class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private RevocationStore $revocations)
    {
    }

    /** @param list<ScopeEntityInterface> $scopes */
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        if ($userIdentifier === null || $userIdentifier === '') {
            throw new InvalidArgumentException('The reference provider only issues access tokens for authenticated end users.');
        }

        $token = new AccessToken();
        $token->setClient($clientEntity);
        $token->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // The access token is a signed JWT; revocation state is persisted separately.
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->revocations->revoke($tokenId);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->revocations->isRevoked($tokenId);
    }
}

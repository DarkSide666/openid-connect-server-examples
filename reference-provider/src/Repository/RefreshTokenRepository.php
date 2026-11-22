<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use DarkSide\OpenIdConnectServer\League\RotatingRefreshTokenRepositoryInterface;
use DarkSide\OpenIdConnectServer\League\RefreshTokenConsumptionResult;
use DarkSide\OidcReferenceProvider\Entity\RefreshToken;
use DarkSide\OidcReferenceProvider\Storage\RefreshTokenState;

final class RefreshTokenRepository implements RotatingRefreshTokenRepositoryInterface
{
    private ?string $rotationFamilyId = null;

    public function __construct(private readonly RefreshTokenState $state)
    {
    }

    public function getNewRefreshToken(): RefreshTokenEntityInterface
    {
        return new RefreshToken();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $tokenId = $refreshTokenEntity->getIdentifier();
        $familyId = $this->rotationFamilyId ?? $tokenId;
        $this->state->create($tokenId, [
            'expires_at' => $refreshTokenEntity->getExpiryDateTime()->getTimestamp(),
            'access_token_id' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
        ], $familyId);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $this->state->revoke($tokenId);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return $this->state->isRevoked($tokenId);
    }

    public function consumeRefreshToken(string $refreshTokenId): RefreshTokenConsumptionResult
    {
        return $this->state->consume($refreshTokenId);
    }

    public function beginRotation(string $refreshTokenId): void
    {
        $this->rotationFamilyId = $this->state->family($refreshTokenId);
    }

    public function endRotation(): void
    {
        $this->rotationFamilyId = null;
    }

    public function revokeFamilyForReusedToken(string $refreshTokenId): void
    {
        $this->state->revokeFamily($refreshTokenId);
    }
}

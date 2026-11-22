<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return null;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        throw new \LogicException('The reference provider does not issue refresh tokens.');
    }

    public function revokeRefreshToken(string $tokenId): void
    {
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return true;
    }
}

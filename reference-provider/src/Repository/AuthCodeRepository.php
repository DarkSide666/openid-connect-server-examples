<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Repository;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use DarkSide\OidcReferenceProvider\Entity\AuthCode;
use DarkSide\OidcReferenceProvider\Storage\RevocationStore;

final readonly class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private RevocationStore $revocations)
    {
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        // League carries the opaque authorization-code entity data in its signed code.
        // OIDC nonce/max_age metadata is persisted separately by OidcAuthCodeRepository.
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->revocations->revoke($codeId);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return $this->revocations->isRevoked($codeId);
    }
}

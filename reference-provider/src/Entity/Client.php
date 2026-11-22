<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Entity;

use InvalidArgumentException;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

final class Client implements ClientEntityInterface
{
    use EntityTrait;

    public function __construct(
        string $id,
        private string $name,
        private string $redirectUri,
        private bool $confidential = true,
    ) {
        if ($id === '' || $name === '' || $redirectUri === '') {
            throw new InvalidArgumentException('Client identifier, name and redirect URI must not be empty.');
        }

        $this->setIdentifier($id);
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, ['authorization_code', 'refresh_token'], true);
    }
}

<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Entity;

use InvalidArgumentException;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

final class User implements UserEntityInterface
{
    use EntityTrait;

    public function __construct(string $identifier)
    {
        if ($identifier === '') {
            throw new InvalidArgumentException('User identifier must not be empty.');
        }

        $this->setIdentifier($identifier);
    }
}

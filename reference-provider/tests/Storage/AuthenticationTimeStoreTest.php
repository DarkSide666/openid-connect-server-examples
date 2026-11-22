<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests\Storage;

use PHPUnit\Framework\TestCase;
use DarkSide\OidcReferenceProvider\Storage\AuthenticationTimeStore;

final class AuthenticationTimeStoreTest extends TestCase
{
    public function testSuccessfulLoginTimeIsAvailableToLaterTokenRequests(): void
    {
        $path = sys_get_temp_dir() . '/darkside-oidc-auth-time-' . bin2hex(random_bytes(8)) . '.json';
        try {
            $loginStore = new AuthenticationTimeStore($path);
            self::assertNull($loginStore->current());
            $loginStore->recordSuccessfulLogin();

            $tokenRequestStore = new AuthenticationTimeStore($path);
            $authenticationTime = $tokenRequestStore->current();

            self::assertNotNull($authenticationTime);
            self::assertLessThanOrEqual(time(), $authenticationTime->getTimestamp());
            self::assertGreaterThanOrEqual(time() - 2, $authenticationTime->getTimestamp());
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}

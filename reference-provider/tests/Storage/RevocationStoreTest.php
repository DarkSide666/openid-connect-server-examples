<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests\Storage;

use PHPUnit\Framework\TestCase;
use DarkSide\OidcReferenceProvider\Storage\RevocationStore;

final class RevocationStoreTest extends TestCase
{
    public function testRevocationPersistsAcrossStoreInstances(): void
    {
        $path = sys_get_temp_dir() . '/darkside-oidc-revocations-' . bin2hex(random_bytes(8)) . '.json';
        try {
            $first = new RevocationStore($path);
            self::assertFalse($first->isRevoked('token-1'));
            $first->revoke('token-1');

            $second = new RevocationStore($path);
            self::assertTrue($second->isRevoked('token-1'));
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}

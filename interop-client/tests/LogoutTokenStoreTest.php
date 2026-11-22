<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient\Tests;

use DarkSide\OidcInteropClient\LogoutTokenStore;
use PHPUnit\Framework\TestCase;

final class LogoutTokenStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/darkside-rp-logout-' . bin2hex(random_bytes(8)) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLogoutTokenIdsAreClaimedOnce(): void
    {
        $store = new LogoutTokenStore($this->path);
        $expiry = time() + 120;

        self::assertTrue($store->claim('https://op.example', 'client-1', 'jti-1', $expiry));
        self::assertFalse($store->claim('https://op.example', 'client-1', 'jti-1', $expiry));
        self::assertTrue($store->claim('https://op.example', 'client-2', 'jti-1', $expiry));
    }

    public function testSessionLogoutTargetsSidWhileSubjectLogoutTargetsAllSessions(): void
    {
        $store = new LogoutTokenStore($this->path);
        $store->revokeSession('subject-1', 'session-1');

        self::assertTrue($store->isSessionRevoked('subject-1', 'session-1'));
        self::assertFalse($store->isSessionRevoked('subject-1', 'session-2'));

        $store->revokeSession('subject-1', null);
        self::assertTrue($store->isSessionRevoked('subject-1', 'session-2'));
    }
}

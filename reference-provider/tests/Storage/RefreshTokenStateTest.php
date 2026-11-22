<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests\Storage;

use DarkSide\OpenIdConnectServer\League\RefreshTokenConsumptionResult;
use DarkSide\OidcReferenceProvider\Storage\RefreshTokenState;
use PHPUnit\Framework\TestCase;

final class RefreshTokenStateTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/darkside-refresh-token-' . bin2hex(random_bytes(8)) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testConsumptionIsAtomicAndReuseRevokesTheWholeTokenFamily(): void
    {
        $state = new RefreshTokenState($this->path);
        $state->create('first', ['expires_at' => time() + 60], 'family-1');
        $state->create('replacement', ['expires_at' => time() + 120], 'family-1');

        self::assertSame(RefreshTokenConsumptionResult::CONSUMED, $state->consume('first'));
        self::assertSame(RefreshTokenConsumptionResult::REPLAYED, $state->consume('first'));
        $state->revokeFamily('first');
        $state->create('late-replacement', ['expires_at' => time() + 180], 'family-1');

        self::assertTrue($state->isRevoked('first'));
        self::assertTrue($state->isRevoked('replacement'));
        self::assertTrue($state->isRevoked('late-replacement'));
    }

    public function testUnknownAndExpiredTokensCannotBeConsumed(): void
    {
        $state = new RefreshTokenState($this->path);
        $state->create('expired', ['expires_at' => time() - 1], 'family-2');

        self::assertSame(RefreshTokenConsumptionResult::INVALID, $state->consume('missing'));
        self::assertSame(RefreshTokenConsumptionResult::INVALID, $state->consume('expired'));
    }
}

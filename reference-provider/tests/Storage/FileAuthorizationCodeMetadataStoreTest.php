<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests\Storage;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use DarkSide\OpenIdConnectServer\Transaction\AuthorizationCodeMetadata;
use DarkSide\OidcReferenceProvider\Storage\FileAuthorizationCodeMetadataStore;

final class FileAuthorizationCodeMetadataStoreTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/darkside-oidc-reference-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->directory);
    }

    public function testMetadataCanBeConsumedExactlyOnceAcrossStoreInstances(): void
    {
        $path = $this->directory . '/metadata.json';
        $firstStore = new FileAuthorizationCodeMetadataStore($path);
        $firstStore->store('auth-code-id', new AuthorizationCodeMetadata('nonce-123', new DateTimeImmutable('+5 minutes'), 120));

        $secondStore = new FileAuthorizationCodeMetadataStore($path);
        $metadata = $secondStore->consume('auth-code-id');

        self::assertNotNull($metadata);
        self::assertSame('nonce-123', $metadata->nonce);
        self::assertSame(120, $metadata->maxAge);
        self::assertNull($firstStore->consume('auth-code-id'));
    }

    public function testExpiredMetadataIsDiscarded(): void
    {
        $store = new FileAuthorizationCodeMetadataStore($this->directory . '/metadata.json');
        $store->store('expired-code', new AuthorizationCodeMetadata('nonce-expired', new DateTimeImmutable('-1 second')));

        self::assertNull($store->consume('expired-code'));
        self::assertNull($store->consume('expired-code'));
    }

    public function testDuplicateMetadataIsRejected(): void
    {
        $store = new FileAuthorizationCodeMetadataStore($this->directory . '/metadata.json');
        $metadata = new AuthorizationCodeMetadata('nonce-123', new DateTimeImmutable('+5 minutes'));
        $store->store('duplicate-code', $metadata);

        $this->expectException(\LogicException::class);
        $store->store('duplicate-code', $metadata);
    }
}

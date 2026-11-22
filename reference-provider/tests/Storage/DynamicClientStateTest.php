<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests\Storage;

use DarkSide\OpenIdConnectServer\Registration\RegisteredClient;
use DarkSide\OidcReferenceProvider\Repository\ClientRepository;
use DarkSide\OidcReferenceProvider\Storage\DynamicClientState;
use PHPUnit\Framework\TestCase;

final class DynamicClientStateTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/darkside-dynamic-clients-' . bin2hex(random_bytes(8)) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testStoresHashedSecretAndMakesRegisteredClientUsable(): void
    {
        $state = new DynamicClientState($this->path);
        $state->create(new RegisteredClient('dynamic-1', [
            'client_name' => 'Dynamic Test RP',
            'redirect_uris' => ['https://rp.example.test/callback'],
            'grant_types' => ['authorization_code'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ], 'one-time-secret'));

        $stored = $state->get('dynamic-1');
        self::assertIsArray($stored);
        self::assertNotSame('one-time-secret', $stored['client_secret_hash'] ?? null);
        self::assertTrue($state->validatesSecret('dynamic-1', 'one-time-secret'));

        $clients = new ClientRepository('static-1', 'static-secret', 'https://rp.example.test/static', $state);
        $client = $clients->getClientEntity('dynamic-1');
        self::assertNotNull($client);
        self::assertSame('https://rp.example.test/callback', $client->getRedirectUri());
        self::assertTrue($client->supportsGrantType('authorization_code'));
        self::assertFalse($client->supportsGrantType('refresh_token'));
        self::assertTrue($clients->validateClient('dynamic-1', 'one-time-secret', 'authorization_code'));
        self::assertFalse($clients->validateClient('dynamic-1', 'wrong', 'authorization_code'));
    }
}

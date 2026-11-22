<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests;

use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;
use DarkSide\OidcReferenceProvider\ProviderFactory;

final class ProviderFactoryTest extends TestCase
{
    private string $directory;
    /** @var array<string, string|false> */
    private array $previousEnvironment = [];

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/darkside-oidc-provider-' . bin2hex(random_bytes(8));
        mkdir($this->directory . '/var/keys', 0700, true);

        $this->writeKeyPair('oauth');
        $this->writeKeyPair('oidc');
        file_put_contents(
            $this->directory . '/var/keys/oauth-encryption.key',
            Key::createNewRandomKey()->saveToAsciiSafeString(),
        );

        $this->setEnvironment('OIDC_REFERENCE_BASE_URL', 'https://reference.example.test');
        $this->setEnvironment('OIDC_REFERENCE_CLIENT_ID', 'provider-test-client');
        $this->setEnvironment('OIDC_REFERENCE_CLIENT_SECRET', 'provider-test-secret');
        $this->setEnvironment('OIDC_REFERENCE_REDIRECT_URI', 'https://client.example.test/callback');
        $this->setEnvironment('OIDC_REFERENCE_TEST_USERNAME', 'alice');
        $this->setEnvironment('OIDC_REFERENCE_TEST_PASSWORD', 'test-password');
        $this->setEnvironment('OIDC_REFERENCE_DATA_DIR', $this->directory . '/var');
    }

    protected function tearDown(): void
    {
        foreach ($this->previousEnvironment as $name => $value) {
            if ($value === false) {
                putenv($name);
                unset($_ENV[$name]);
            } else {
                putenv($name . '=' . $value);
                $_ENV[$name] = $value;
            }
        }
        $this->removeDirectory($this->directory);
    }

    public function testFactoryWiresTheAdvertisedAuthorizationCodeProviderProfile(): void
    {
        $services = (new ProviderFactory($this->directory))->create();
        $metadata = $services['discovery']->generate();

        self::assertSame('https://reference.example.test', $metadata['issuer']);
        self::assertSame('https://reference.example.test/authorize', $metadata['authorization_endpoint']);
        self::assertSame('https://reference.example.test/token', $metadata['token_endpoint']);
        self::assertSame('https://reference.example.test/jwks', $metadata['jwks_uri']);
        self::assertSame('https://reference.example.test/userinfo', $metadata['userinfo_endpoint']);
        self::assertSame(['code'], $metadata['response_types_supported']);
        self::assertSame(['authorization_code'], $metadata['grant_types_supported']);
        self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        self::assertSame(['client_secret_basic'], $metadata['token_endpoint_auth_methods_supported']);
        self::assertSame('provider-test-client', $services['clientId']);
        self::assertSame('alice', $services['username']);

        $jwks = $services['jwks']->generate();
        self::assertCount(1, $jwks['keys']);
        self::assertSame('reference-rs256-2026', $jwks['keys'][0]['kid']);
        self::assertArrayNotHasKey('d', $jwks['keys'][0]);
    }

    private function writeKeyPair(string $prefix): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($key);
        self::assertTrue(openssl_pkey_export($key, $privatePem));
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($details['key'] ?? null);
        file_put_contents($this->directory . '/var/keys/' . $prefix . '-private.pem', $privatePem);
        file_put_contents($this->directory . '/var/keys/' . $prefix . '-public.pem', $details['key']);
    }

    private function setEnvironment(string $name, string $value): void
    {
        $this->previousEnvironment[$name] = getenv($name);
        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
    }

    private function removeDirectory(string $directory): void
    {
        foreach (glob($directory . '/*') ?: [] as $path) {
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($directory);
    }
}

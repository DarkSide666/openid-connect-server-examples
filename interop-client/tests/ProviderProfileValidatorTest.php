<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use DarkSide\OidcInteropClient\ProviderProfileValidator;

final class ProviderProfileValidatorTest extends TestCase
{
    public function testAcceptsReferenceProviderDiscoveryProfile(): void
    {
        $metadata = [
            'issuer' => 'https://oidc-reference.loc',
            'authorization_endpoint' => 'https://oidc-reference.loc/authorize',
            'token_endpoint' => 'https://oidc-reference.loc/token',
            'jwks_uri' => 'https://oidc-reference.loc/jwks',
            'userinfo_endpoint' => 'https://oidc-reference.loc/userinfo',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_modes_supported' => ['query'],
            'code_challenge_methods_supported' => ['S256'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
        ];

        (new ProviderProfileValidator())->validateDiscovery($metadata, 'https://oidc-reference.loc');
        self::assertTrue(true);
    }

    public function testRejectsIssuerMismatch(): void
    {
        $metadata = $this->validMetadata();
        $metadata['issuer'] = 'https://attacker.example';

        $this->expectException(RuntimeException::class);
        (new ProviderProfileValidator())->validateDiscovery($metadata, 'https://oidc-reference.loc');
    }

    public function testRejectsInsecureAuthorizationEndpoint(): void
    {
        $metadata = $this->validMetadata();
        $metadata['authorization_endpoint'] = 'http://oidc-reference.loc/authorize';

        $this->expectException(RuntimeException::class);
        (new ProviderProfileValidator())->validateDiscovery($metadata, 'https://oidc-reference.loc');
    }

    public function testRejectsMissingPkceS256(): void
    {
        $metadata = $this->validMetadata();
        $metadata['code_challenge_methods_supported'] = ['plain'];

        $this->expectException(RuntimeException::class);
        (new ProviderProfileValidator())->validateDiscovery($metadata, 'https://oidc-reference.loc');
    }

    public function testAcceptsPublicRs256Jwks(): void
    {
        $jwks = ['keys' => [[
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'test-key',
            'n' => 'public-modulus',
            'e' => 'AQAB',
        ]]];

        (new ProviderProfileValidator())->validateJwks($jwks);
        self::assertTrue(true);
    }

    public function testRejectsPrivateKeyMaterialInJwks(): void
    {
        $jwks = ['keys' => [[
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'test-key',
            'n' => 'public-modulus',
            'e' => 'AQAB',
            'd' => 'must-not-be-published',
        ]]];

        $this->expectException(RuntimeException::class);
        (new ProviderProfileValidator())->validateJwks($jwks);
    }

    /** @return array<string, mixed> */
    private function validMetadata(): array
    {
        return [
            'issuer' => 'https://oidc-reference.loc',
            'authorization_endpoint' => 'https://oidc-reference.loc/authorize',
            'token_endpoint' => 'https://oidc-reference.loc/token',
            'jwks_uri' => 'https://oidc-reference.loc/jwks',
            'userinfo_endpoint' => 'https://oidc-reference.loc/userinfo',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_modes_supported' => ['query'],
            'code_challenge_methods_supported' => ['S256'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
        ];
    }
}

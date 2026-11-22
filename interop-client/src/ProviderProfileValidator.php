<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient;

use RuntimeException;

final class ProviderProfileValidator
{
    /** @param array<string, mixed> $metadata */
    public function validateDiscovery(array $metadata, string $expectedIssuer): void
    {
        $this->requireSame($metadata['issuer'] ?? null, $expectedIssuer, 'issuer');

        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint'] as $endpoint) {
            $this->requireHttpsEndpoint($metadata[$endpoint] ?? null, $endpoint);
        }

        $this->requireContains($metadata['response_types_supported'] ?? null, 'code', 'response_types_supported');
        $this->requireContains($metadata['grant_types_supported'] ?? null, 'authorization_code', 'grant_types_supported');
        $this->requireContains($metadata['response_modes_supported'] ?? null, 'query', 'response_modes_supported');
        $this->requireContains($metadata['code_challenge_methods_supported'] ?? null, 'S256', 'code_challenge_methods_supported');
        $this->requireContains($metadata['id_token_signing_alg_values_supported'] ?? null, 'RS256', 'id_token_signing_alg_values_supported');
        $this->requireContains($metadata['token_endpoint_auth_methods_supported'] ?? null, 'client_secret_basic', 'token_endpoint_auth_methods_supported');

        $scopes = $metadata['scopes_supported'] ?? null;
        foreach (['openid', 'profile', 'email'] as $scope) {
            $this->requireContains($scopes, $scope, 'scopes_supported');
        }
    }

    /** @param array<string, mixed> $jwks */
    public function validateJwks(array $jwks): void
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys) || $keys === []) {
            throw new RuntimeException('JWKS must contain at least one public key.');
        }

        $matchingKeyFound = false;
        foreach ($keys as $key) {
            if (!is_array($key)) {
                throw new RuntimeException('Every JWKS key must be a JSON object.');
            }
            if (($key['kty'] ?? null) === 'RSA'
                && ($key['use'] ?? null) === 'sig'
                && ($key['alg'] ?? null) === 'RS256'
                && is_string($key['kid'] ?? null)
                && $key['kid'] !== ''
                && is_string($key['n'] ?? null)
                && $key['n'] !== ''
                && is_string($key['e'] ?? null)
                && $key['e'] !== '') {
                $matchingKeyFound = true;
            }

            foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as $privateParameter) {
                if (array_key_exists($privateParameter, $key)) {
                    throw new RuntimeException('JWKS must never publish private RSA key parameters.');
                }
            }
        }

        if (!$matchingKeyFound) {
            throw new RuntimeException('JWKS does not contain a usable RS256 signing key.');
        }
    }

    private function requireHttpsEndpoint(mixed $value, string $name): void
    {
        if (!is_string($value)) {
            throw new RuntimeException(sprintf('Discovery metadata must advertise an HTTPS %s.', $name));
        }

        $parts = parse_url($value);
        if (!is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])) {
            throw new RuntimeException(sprintf('Discovery metadata must advertise a valid HTTPS %s.', $name));
        }
    }

    private function requireSame(mixed $actual, string $expected, string $name): void
    {
        if (!is_string($actual) || !hash_equals($expected, $actual)) {
            throw new RuntimeException(sprintf('Discovery %s does not match the configured value.', $name));
        }
    }

    private function requireContains(mixed $values, string $expected, string $name): void
    {
        if (!is_array($values) || !in_array($expected, $values, true)) {
            throw new RuntimeException(sprintf('Discovery %s must include %s.', $name, $expected));
        }
    }
}

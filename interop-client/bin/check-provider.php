<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;
use DarkSide\OidcInteropClient\ProviderProfileValidator;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

try {
    $config = Config::fromEnvironment();
    $validator = new ProviderProfileValidator();

    $fetchJson = static function (string $url) use ($config): array {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize cURL.');
        }

        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        if ($config->caBundle !== null && $config->caBundle !== '') {
            curl_setopt($handle, CURLOPT_CAINFO, $config->caBundle);
        }

        $body = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);

        if (!is_string($body)) {
            throw new RuntimeException('HTTPS request failed: ' . $error);
        }
        if ($status !== 200) {
            throw new RuntimeException(sprintf('GET %s returned HTTP %d.', $url, $status));
        }

        $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException(sprintf('GET %s did not return a JSON object.', $url));
        }

        return $decoded;
    };

    $discovery = $fetchJson($config->providerIssuer . '/.well-known/openid-configuration');
    $validator->validateDiscovery($discovery, $config->providerIssuer);
    echo "PASS: discovery document matches the expected Authorization Code + PKCE S256 + RS256 profile.\n";

    $jwksUri = $discovery['jwks_uri'];
    if (!is_string($jwksUri)) {
        throw new RuntimeException('Discovery jwks_uri is invalid.');
    }
    $jwks = $fetchJson($jwksUri);
    $validator->validateJwks($jwks);
    echo "PASS: JWKS publishes a usable RS256 public key and no private RSA parameters.\n";
    echo "PASS: TLS certificate verification succeeded for discovery and JWKS.\n";
    echo "\nNext: open the interop client in a browser and start the Authorization Code flow.\n";
} catch (Throwable $exception) {
    fwrite(STDERR, 'FAIL: ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}

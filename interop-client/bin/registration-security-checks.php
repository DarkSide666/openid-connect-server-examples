<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

$config = Config::fromEnvironment();
$registrationToken = trim((string) getenv('OIDC_INTEROP_REGISTRATION_INITIAL_ACCESS_TOKEN'));
$curl = static function (string $url, array $headers = [], ?string $body = null) use ($config): array {
    $handle = curl_init($url);
    if ($handle === false) {
        throw new RuntimeException('Unable to initialize registration request.');
    }
    $options = [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false, CURLOPT_HTTPHEADER => $headers];
    if ($config->caBundle !== null) {
        $options[CURLOPT_CAINFO] = $config->caBundle;
    }
    if ($body !== null) {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = $body;
    }
    curl_setopt_array($handle, $options);
    $responseBody = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    if (!is_string($responseBody)) {
        $message = curl_error($handle);
        curl_close($handle);
        throw new RuntimeException('Registration request failed: ' . $message);
    }
    curl_close($handle);
    $payload = json_decode($responseBody, true);
    return ['status' => $status, 'payload' => is_array($payload) ? $payload : []];
};

try {
    $metadataResponse = $curl($config->providerIssuer . '/.well-known/openid-configuration', ['Accept: application/json']);
    $endpoint = $metadataResponse['payload']['registration_endpoint'] ?? null;
    if (!is_string($endpoint) || $endpoint === '') {
        echo "SKIP Dynamic Client Registration is not enabled by provider configuration.\n";
        exit(0);
    }
    $endpointParts = parse_url($endpoint);
    if (!is_array($endpointParts) || strtolower((string) ($endpointParts['scheme'] ?? '')) !== 'https'
        || ($endpointParts['host'] ?? null) !== parse_url($config->providerIssuer, PHP_URL_HOST)) {
        throw new RuntimeException('Provider registration endpoint must be HTTPS on the configured issuer host.');
    }
    if ($registrationToken === '') {
        throw new RuntimeException('Provider advertises registration but OIDC_INTEROP_REGISTRATION_INITIAL_ACCESS_TOKEN is not configured.');
    }
    $metadata = [
        'client_name' => 'Interop Dynamic Test Client',
        'redirect_uris' => [$config->redirectUri],
        'response_types' => ['code'],
        'grant_types' => ['authorization_code'],
        'token_endpoint_auth_method' => 'client_secret_basic',
    ];
    $registered = $curl($endpoint, [
        'Accept: application/json',
        'Content-Type: application/json',
        'Authorization: Bearer ' . $registrationToken,
    ], json_encode($metadata, JSON_THROW_ON_ERROR));
    if ($registered['status'] !== 201 || !is_string($registered['payload']['client_id'] ?? null)
        || !is_string($registered['payload']['client_secret'] ?? null)) {
        throw new RuntimeException('Protected registration did not return a client ID and one-time client secret.');
    }
    echo "PASS Protected registration creates a client and returns its secret once.\n";

    $unauthorized = $curl($endpoint, ['Content-Type: application/json', 'Authorization: Bearer incorrect'], json_encode($metadata, JSON_THROW_ON_ERROR));
    if ($unauthorized['status'] !== 403) {
        throw new RuntimeException('Registration accepted an invalid initial access token.');
    }
    echo "PASS Registration rejects an invalid initial access token.\n";

    $unsafe = $metadata;
    $unsafe['redirect_uris'] = ['http://attacker.example.test/callback'];
    $invalid = $curl($endpoint, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $registrationToken,
    ], json_encode($unsafe, JSON_THROW_ON_ERROR));
    if ($invalid['status'] !== 400) {
        throw new RuntimeException('Registration accepted an insecure redirect URI.');
    }
    echo "PASS Registration rejects insecure redirect URIs.\n";
} catch (Throwable $exception) {
    fwrite(STDERR, 'Registration security checks failed: ' . $exception->getMessage() . "\n");
    exit(1);
}

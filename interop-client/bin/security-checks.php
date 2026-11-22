<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

$config = Config::fromEnvironment();

/** @return array{status: int, headers: array<string, string>, body: string} */
$http = static function (string $method, string $url, array $headers = [], ?string $body = null) use ($config): array {
    $handle = curl_init($url);
    if ($handle === false) {
        throw new RuntimeException('Unable to initialize cURL.');
    }

    $responseHeaders = [];
    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
            $length = strlen($line);
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
            }

            return $length;
        },
    ];
    if ($body !== null) {
        $options[CURLOPT_POSTFIELDS] = $body;
    }
    if ($config->caBundle !== null) {
        $options[CURLOPT_CAINFO] = $config->caBundle;
    }

    curl_setopt_array($handle, $options);
    $responseBody = curl_exec($handle);
    if (!is_string($responseBody)) {
        $message = curl_error($handle);
        curl_close($handle);
        throw new RuntimeException('HTTPS request failed: ' . $message);
    }

    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);

    return ['status' => $status, 'headers' => $responseHeaders, 'body' => $responseBody];
};

$checks = [];
$record = static function (string $name, bool $passed, string $detail) use (&$checks): void {
    $checks[] = ['name' => $name, 'passed' => $passed, 'detail' => $detail];
};

$issuer = $config->providerIssuer;
$discovery = $http('GET', $issuer . '/.well-known/openid-configuration', ['Accept: application/json']);
$discoveryDocument = json_decode($discovery['body'], true);
$record(
    'Discovery endpoint is reachable over verified HTTPS',
    $discovery['status'] === 200 && is_array($discoveryDocument)
        && ($discoveryDocument['issuer'] ?? null) === $issuer,
    'HTTP ' . $discovery['status'] . '; issuer matches configured origin: '
        . (($discoveryDocument['issuer'] ?? null) === $issuer ? 'yes' : 'no'),
);

$tokenUrl = is_array($discoveryDocument) && is_string($discoveryDocument['token_endpoint'] ?? null)
    ? $discoveryDocument['token_endpoint']
    : $issuer . '/token';
$userInfoUrl = is_array($discoveryDocument) && is_string($discoveryDocument['userinfo_endpoint'] ?? null)
    ? $discoveryDocument['userinfo_endpoint']
    : $issuer . '/userinfo';

$basic = static fn (string $secret): string => 'Authorization: Basic ' . base64_encode($config->clientId . ':' . $secret);
$formHeaders = ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'];
$decodeError = static function (array $response): ?string {
    $payload = json_decode($response['body'], true);

    return is_array($payload) && is_string($payload['error'] ?? null) ? $payload['error'] : null;
};

$invalidClient = $http('POST', $tokenUrl, [...$formHeaders, $basic('deliberately-incorrect-secret')], http_build_query([
    'grant_type' => 'authorization_code',
    'code' => 'security-probe-invalid-code',
    'redirect_uri' => $config->redirectUri,
]));
$invalidClientError = $decodeError($invalidClient);
$record(
    'Token endpoint rejects incorrect client credentials',
    $invalidClient['status'] === 401 && $invalidClientError !== null,
    'HTTP ' . $invalidClient['status'] . '; OAuth error: ' . ($invalidClientError ?? 'missing'),
);

$invalidCode = $http('POST', $tokenUrl, [...$formHeaders, $basic($config->clientSecret)], http_build_query([
    'grant_type' => 'authorization_code',
    'code' => 'security-probe-invalid-code',
    'redirect_uri' => $config->redirectUri,
]));
$invalidCodeError = $decodeError($invalidCode);
$record(
    'Token endpoint rejects an unknown authorization code',
    $invalidCode['status'] === 400 && $invalidCodeError !== null,
    'HTTP ' . $invalidCode['status'] . '; OAuth error: ' . ($invalidCodeError ?? 'missing'),
);

$missingCode = $http('POST', $tokenUrl, [...$formHeaders, $basic($config->clientSecret)], http_build_query([
    'grant_type' => 'authorization_code',
    'redirect_uri' => $config->redirectUri,
]));
$missingCodeError = $decodeError($missingCode);
$record(
    'Token endpoint rejects a missing authorization code',
    $missingCode['status'] === 400 && $missingCodeError !== null,
    'HTTP ' . $missingCode['status'] . '; OAuth error: ' . ($missingCodeError ?? 'missing'),
);

$unsupportedGrant = $http('POST', $tokenUrl, [...$formHeaders, $basic($config->clientSecret)], http_build_query([
    'grant_type' => 'refresh_token',
    'refresh_token' => 'security-probe-refresh-token',
]));
$unsupportedGrantError = $decodeError($unsupportedGrant);
$record(
    'Token endpoint rejects the unsupported refresh-token grant',
    $unsupportedGrant['status'] === 400 && $unsupportedGrantError !== null,
    'HTTP ' . $unsupportedGrant['status'] . '; OAuth error: ' . ($unsupportedGrantError ?? 'missing'),
);

$noBearer = $http('GET', $userInfoUrl, ['Accept: application/json']);
$record(
    'UserInfo rejects a request without a Bearer token',
    $noBearer['status'] === 401,
    'HTTP ' . $noBearer['status'],
);

$malformedBearer = $http('GET', $userInfoUrl, ['Accept: application/json', 'Authorization: Bearer not-a-valid-access-token']);
$record(
    'UserInfo rejects a malformed/unknown Bearer token',
    $malformedBearer['status'] === 401,
    'HTTP ' . $malformedBearer['status'],
);

$passed = count(array_filter($checks, static fn (array $check): bool => $check['passed']));
foreach ($checks as $check) {
    printf("%s %s — %s\n", $check['passed'] ? 'PASS' : 'FAIL', $check['name'], $check['detail']);
}
printf("\n%d/%d negative interoperability checks passed.\n", $passed, count($checks));

exit($passed === count($checks) ? 0 : 1);

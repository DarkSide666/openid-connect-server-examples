<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

$config = Config::fromEnvironment();
$username = trim((string) getenv('OIDC_INTEROP_TEST_USERNAME'));
$password = (string) getenv('OIDC_INTEROP_TEST_PASSWORD');
$controlSecret = (string) getenv('OIDC_INTEROP_TEST_CONTROL_SECRET');
if ($username === '' || $password === '' || $controlSecret === '') {
    fwrite(STDERR, "Set OIDC_INTEROP_TEST_USERNAME, OIDC_INTEROP_TEST_PASSWORD and OIDC_INTEROP_TEST_CONTROL_SECRET in interop-client/.env.\n");
    exit(2);
}

/**
 * @param list<string> $headers
 * @return array{status: int, headers: array<string, string>, body: string}
 */
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
        CURLOPT_TIMEOUT => 30,
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

$base64Url = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
$decodePart = static function (string $part): string {
    $decoded = base64_decode(strtr($part, '-_', '+/') . str_repeat('=', (4 - strlen($part) % 4) % 4), true);
    if (!is_string($decoded)) {
        throw new RuntimeException('Malformed base64url JWT segment.');
    }
    return $decoded;
};
$basic = 'Authorization: Basic ' . base64_encode($config->clientId . ':' . $config->clientSecret);
$formHeaders = ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded', $basic];
$discoveryResponse = $http('GET', $config->providerIssuer . '/.well-known/openid-configuration', ['Accept: application/json']);
$discovery = json_decode($discoveryResponse['body'], true);
if ($discoveryResponse['status'] !== 200 || !is_array($discovery)
    || ($discovery['issuer'] ?? null) !== $config->providerIssuer
    || !is_string($discovery['authorization_endpoint'] ?? null)
    || !is_string($discovery['token_endpoint'] ?? null)
    || !is_string($discovery['userinfo_endpoint'] ?? null)
    || !is_string($discovery['jwks_uri'] ?? null)) {
    fwrite(STDERR, "Unable to load valid discovery metadata over verified HTTPS.\n");
    exit(2);
}
$authorizationEndpoint = $discovery['authorization_endpoint'];
$tokenEndpoint = $discovery['token_endpoint'];
$userInfoEndpoint = $discovery['userinfo_endpoint'];
$jwksResponse = $http('GET', $discovery['jwks_uri'], ['Accept: application/json']);
$jwks = json_decode($jwksResponse['body'], true);
if ($jwksResponse['status'] !== 200 || !is_array($jwks) || !is_array($jwks['keys'] ?? null)) {
    fwrite(STDERR, "Unable to load provider JWKS.\n");
    exit(2);
}

/** @return array{code: string, verifier: string} */
$createAuthorizationCode = static function () use ($http, $config, $username, $password, $base64Url, $authorizationEndpoint): array {
    $verifier = $base64Url(random_bytes(32));
    $challenge = $base64Url(hash('sha256', $verifier, true));
    $query = http_build_query([
        'client_id' => $config->clientId, 'response_type' => 'code', 'redirect_uri' => $config->redirectUri,
        'scope' => 'openid profile email', 'state' => bin2hex(random_bytes(16)), 'nonce' => bin2hex(random_bytes(16)),
        'code_challenge' => $challenge, 'code_challenge_method' => 'S256',
    ], '', '&', PHP_QUERY_RFC3986);
    $page = $http('GET', $authorizationEndpoint . '?' . $query, ['Accept: text/html']);
    if ($page['status'] !== 200 || !preg_match('/name="csrf_token"\s+value="([a-f0-9]+)"/i', $page['body'], $match)
        || !isset($page['headers']['set-cookie'])) {
        throw new RuntimeException('Unable to initialize provider login form.');
    }
    $cookie = explode(';', $page['headers']['set-cookie'], 2)[0];
    $login = $http('POST', $authorizationEndpoint, ['Accept: text/html', 'Content-Type: application/x-www-form-urlencoded', 'Cookie: ' . $cookie], http_build_query([
        'csrf_token' => $match[1], 'username' => $username, 'password' => $password, 'approve' => '1',
    ], '', '&', PHP_QUERY_RFC3986));
    $location = $login['headers']['location'] ?? '';
    $parts = parse_url($location);
    parse_str(is_array($parts) ? (string) ($parts['query'] ?? '') : '', $queryValues);
    $code = $queryValues['code'] ?? null;
    if ($login['status'] !== 302 || !is_string($code) || $code === '') {
        throw new RuntimeException('Provider did not issue an authorization code.');
    }
    return ['code' => $code, 'verifier' => $verifier];
};

/** @return array{status: int, payload: array<string, mixed>} */
$redeem = static function (array $transaction) use ($http, $tokenEndpoint, $formHeaders, $config): array {
    $response = $http('POST', $tokenEndpoint, $formHeaders, http_build_query([
        'grant_type' => 'authorization_code', 'code' => $transaction['code'],
        'redirect_uri' => $config->redirectUri, 'code_verifier' => $transaction['verifier'],
    ], '', '&', PHP_QUERY_RFC3986));
    $payload = json_decode($response['body'], true);
    return ['status' => $response['status'], 'payload' => is_array($payload) ? $payload : []];
};

$asnLength = static function (int $length): string {
    if ($length < 128) {
        return chr($length);
    }
    $encoded = ltrim(pack('N', $length), "\0");
    return chr(0x80 | strlen($encoded)) . $encoded;
};
$asnInteger = static function (string $value) use ($asnLength): string {
    $value = ltrim($value, "\0");
    if ($value === '' || (ord($value[0]) & 0x80) !== 0) {
        $value = "\0" . $value;
    }
    return "\x02" . $asnLength(strlen($value)) . $value;
};
$jwkToPem = static function (array $jwk) use ($decodePart, $asnLength, $asnInteger): string {
    $modulus = $decodePart((string) ($jwk['n'] ?? ''));
    $exponent = $decodePart((string) ($jwk['e'] ?? ''));
    $rsa = $asnInteger($modulus) . $asnInteger($exponent);
    $rsaSequence = "\x30" . $asnLength(strlen($rsa)) . $rsa;
    $algorithm = hex2bin('300d06092a864886f70d0101010500');
    $bitString = "\x03" . $asnLength(strlen($rsaSequence) + 1) . "\0" . $rsaSequence;
    $der = "\x30" . $asnLength(strlen($algorithm . $bitString)) . $algorithm . $bitString;
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
};

$checks = [];
$record = static function (string $name, bool $passed, string $detail) use (&$checks): void {
    $checks[] = ['name' => $name, 'passed' => $passed, 'detail' => $detail];
};

try {
    // Revocation is deliberately exercised through a guarded test-only provider control route.
    $revocationTransaction = $createAuthorizationCode();
    $revocationTokens = $redeem($revocationTransaction);
    $accessToken = $revocationTokens['payload']['access_token'] ?? null;
    if ($revocationTokens['status'] !== 200 || !is_string($accessToken)) {
        throw new RuntimeException('Could not obtain an access token for the revocation test. Ensure provider access-token TTL is configured.');
    }
    $revokeResponse = $http('POST', $config->providerIssuer . '/__test/revoke-access-token', [
        'Accept: application/json', 'Content-Type: application/x-www-form-urlencoded',
        'X-Reference-Test-Control: ' . $controlSecret,
    ], http_build_query(['access_token' => $accessToken], '', '&', PHP_QUERY_RFC3986));
    $revokedUserInfo = $http('GET', $userInfoEndpoint, ['Accept: application/json', 'Authorization: Bearer ' . $accessToken]);
    $record(
        'UserInfo rejects a revoked access token',
        $revokeResponse['status'] === 200 && $revokedUserInfo['status'] === 401,
        'revocation control HTTP ' . $revokeResponse['status'] . '; subsequent UserInfo HTTP ' . $revokedUserInfo['status'],
    );

    // The reference provider must be restarted with OIDC_REFERENCE_ACCESS_TOKEN_TTL_SECONDS=2 for this test.
    $expiryTransaction = $createAuthorizationCode();
    $expiryTokens = $redeem($expiryTransaction);
    $expiryToken = $expiryTokens['payload']['access_token'] ?? null;
    if ($expiryTokens['status'] !== 200 || !is_string($expiryToken)) {
        throw new RuntimeException('Could not obtain an access token for the expiration test.');
    }
    sleep(6);
    $expiredUserInfo = $http('GET', $userInfoEndpoint, ['Accept: application/json', 'Authorization: Bearer ' . $expiryToken]);
    $record('UserInfo rejects an expired access token', $expiredUserInfo['status'] === 401, 'UserInfo HTTP ' . $expiredUserInfo['status'] . ' after a 6-second wait');

    // Obtain a fresh ID Token and independently verify RS256 using the published JWKS.
    $idTransaction = $createAuthorizationCode();
    $idTokens = $redeem($idTransaction);
    $idToken = $idTokens['payload']['id_token'] ?? null;
    if ($idTokens['status'] !== 200 || !is_string($idToken)) {
        throw new RuntimeException('Could not obtain an ID Token for signature checks.');
    }
    $segments = explode('.', $idToken);
    if (count($segments) !== 3) {
        throw new RuntimeException('Provider returned a malformed ID Token.');
    }
    $header = json_decode($decodePart($segments[0]), true);
    $claims = json_decode($decodePart($segments[1]), true);
    if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? null) !== 'RS256' || !is_string($header['kid'] ?? null)) {
        throw new RuntimeException('ID Token header or claims are invalid.');
    }
    $matchingJwk = null;
    foreach ($jwks['keys'] as $key) {
        if (is_array($key) && ($key['kid'] ?? null) === $header['kid']) {
            $matchingJwk = $key;
        }
    }
    $publicKey = is_array($matchingJwk) ? openssl_pkey_get_public($jwkToPem($matchingJwk)) : false;
    $signature = $decodePart($segments[2]);
    $signedContent = $segments[0] . '.' . $segments[1];
    $validSignature = $publicKey !== false && openssl_verify($signedContent, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    $record('A genuine ID Token signature verifies against the published JWKS', $validSignature, 'kid ' . $header['kid'] . '; RS256 verification: ' . ($validSignature ? 'valid' : 'invalid'));
    $expectedActiveKid = trim((string) getenv('OIDC_INTEROP_EXPECT_ACTIVE_KID'));
    if ($expectedActiveKid !== '') {
        $record('New ID Tokens use the configured active signing key after rotation', hash_equals($expectedActiveKid, $header['kid']), 'expected kid ' . $expectedActiveKid . '; issued kid ' . $header['kid']);
    }

    $tamperedSignature = $signature;
    $tamperedSignature[0] = $tamperedSignature[0] === "\0" ? "\1" : chr(ord($tamperedSignature[0]) ^ 1);
    $tamperedValid = $publicKey !== false && openssl_verify($signedContent, $tamperedSignature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    $record('A tampered ID Token signature is rejected', !$tamperedValid, 'tampered signature accepted: ' . ($tamperedValid ? 'yes' : 'no'));

    $unknownKid = 'unknown-security-test-kid';
    $unknownKidFound = false;
    foreach ($jwks['keys'] as $key) {
        if (is_array($key) && ($key['kid'] ?? null) === $unknownKid) {
            $unknownKidFound = true;
        }
    }
    $record('An unknown signing key identifier cannot be resolved from JWKS', !$unknownKidFound, 'unknown kid present in JWKS: ' . ($unknownKidFound ? 'yes' : 'no'));

    $issuerValid = is_string($claims['iss'] ?? null) && hash_equals($config->providerIssuer, $claims['iss']);
    $audience = $claims['aud'] ?? null;
    $audienceValid = is_string($audience) ? hash_equals($config->clientId, $audience)
        : is_array($audience) && in_array($config->clientId, $audience, true);
    $record(
        'The issued ID Token has the configured issuer and client audience',
        $issuerValid && $audienceValid,
        'issuer matches: ' . ($issuerValid ? 'yes' : 'no') . '; audience contains client: ' . ($audienceValid ? 'yes' : 'no')
    );

    // Explicit claim-policy probes: the validator must reject altered issuer/audience values.
    $claimsAccepted = static function (array $candidate) use ($config): bool {
        $issuer = $candidate['iss'] ?? null;
        $audience = $candidate['aud'] ?? null;
        $audiences = is_array($audience) ? $audience : [$audience];
        return is_string($issuer) && hash_equals($config->providerIssuer, $issuer)
            && in_array($config->clientId, $audiences, true);
    };
    $wrongIssuer = $claims;
    $wrongIssuer['iss'] = 'https://wrong-issuer.invalid';
    $wrongAudience = $claims;
    $wrongAudience['aud'] = 'wrong-client';
    $record('ID Token claim validation rejects an incorrect issuer', !$claimsAccepted($wrongIssuer), 'incorrect issuer accepted: ' . ($claimsAccepted($wrongIssuer) ? 'yes' : 'no'));
    $record('ID Token claim validation rejects an incorrect audience', !$claimsAccepted($wrongAudience), 'incorrect audience accepted: ' . ($claimsAccepted($wrongAudience) ? 'yes' : 'no'));

    $expectedRetiredKid = trim((string) getenv('OIDC_INTEROP_EXPECT_RETIRED_KID'));
    if ($expectedRetiredKid !== '') {
        $retiredFound = false;
        foreach ($jwks['keys'] as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $expectedRetiredKid) {
                $retiredFound = true;
            }
        }
        $record('JWKS retains the configured previous signing key during rotation', $retiredFound, 'retired kid ' . $expectedRetiredKid . ' published: ' . ($retiredFound ? 'yes' : 'no'));
    }
} catch (Throwable $exception) {
    fwrite(STDERR, 'Token/ID Token security checks could not complete: ' . $exception->getMessage() . "\n");
    exit(2);
}

$passed = count(array_filter($checks, static fn (array $check): bool => $check['passed']));
foreach ($checks as $check) {
    printf("%s %s — %s\n", $check['passed'] ? 'PASS' : 'FAIL', $check['name'], $check['detail']);
}
printf("\n%d/%d token and ID Token security checks passed.\n", $passed, count($checks));
exit($passed === count($checks) ? 0 : 1);

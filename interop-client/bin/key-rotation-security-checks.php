<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

$mode = $argv[1] ?? '';
if (!in_array($mode, ['prepare', 'verify'], true)) {
    fwrite(STDERR, "Usage: php bin/key-rotation-security-checks.php <prepare|verify>\n");
    exit(2);
}

$config = Config::fromEnvironment();
$username = trim((string) getenv('OIDC_INTEROP_TEST_USERNAME'));
$password = (string) getenv('OIDC_INTEROP_TEST_PASSWORD');
$oldKid = trim((string) getenv('OIDC_INTEROP_ROTATION_OLD_KID'));
$newKid = trim((string) getenv('OIDC_INTEROP_ROTATION_NEW_KID'));
if ($username === '' || $password === '' || $oldKid === '' || $newKid === '') {
    fwrite(STDERR, "Set OIDC_INTEROP_TEST_USERNAME, OIDC_INTEROP_TEST_PASSWORD, OIDC_INTEROP_ROTATION_OLD_KID and OIDC_INTEROP_ROTATION_NEW_KID in interop-client/.env.\n");
    exit(2);
}
if ($oldKid === $newKid) {
    fwrite(STDERR, "The old and new signing key IDs must be different.\n");
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

$decodePart = static function (string $part): string {
    $decoded = base64_decode(strtr($part, '-_', '+/') . str_repeat('=', (4 - strlen($part) % 4) % 4), true);
    if (!is_string($decoded)) {
        throw new RuntimeException('Malformed base64url JWT segment.');
    }

    return $decoded;
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
    if (!is_string($algorithm)) {
        throw new RuntimeException('Unable to encode the RSA algorithm identifier.');
    }
    $bitString = "\x03" . $asnLength(strlen($rsaSequence) + 1) . "\0" . $rsaSequence;
    $der = "\x30" . $asnLength(strlen($algorithm . $bitString)) . $algorithm . $bitString;

    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
};

/** @return array{header: array<string, mixed>, claims: array<string, mixed>, signature: string, signed_content: string} */
$parseJwt = static function (string $token) use ($decodePart): array {
    $segments = explode('.', $token);
    if (count($segments) !== 3) {
        throw new RuntimeException('Provider returned a malformed ID Token.');
    }
    $header = json_decode($decodePart($segments[0]), true);
    $claims = json_decode($decodePart($segments[1]), true);
    if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? null) !== 'RS256' || !is_string($header['kid'] ?? null)) {
        throw new RuntimeException('ID Token header or claims are invalid.');
    }

    return [
        'header' => $header,
        'claims' => $claims,
        'signature' => $decodePart($segments[2]),
        'signed_content' => $segments[0] . '.' . $segments[1],
    ];
};

/** @param array<string, mixed> $jwks @return array<string, mixed>|null */
$findJwk = static function (array $jwks, string $kid): ?array {
    foreach (($jwks['keys'] ?? []) as $key) {
        if (is_array($key) && ($key['kid'] ?? null) === $kid) {
            return $key;
        }
    }

    return null;
};

/** @param array<string, mixed> $jwt @param array<string, mixed> $jwks */
$verifyJwt = static function (array $jwt, array $jwks, string $expectedIssuer, string $expectedAudience) use ($findJwk, $jwkToPem): bool {
    $kid = $jwt['header']['kid'] ?? null;
    if (!is_string($kid)) {
        return false;
    }
    $jwk = $findJwk($jwks, $kid);
    if ($jwk === null || ($jwk['kty'] ?? null) !== 'RSA' || ($jwk['alg'] ?? null) !== 'RS256') {
        return false;
    }
    $publicKey = openssl_pkey_get_public($jwkToPem($jwk));
    if ($publicKey === false || openssl_verify($jwt['signed_content'], $jwt['signature'], $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
        return false;
    }
    $claims = $jwt['claims'];
    $audience = $claims['aud'] ?? null;
    $audiences = is_array($audience) ? $audience : [$audience];
    $expiresAt = $claims['exp'] ?? null;

    return is_string($claims['iss'] ?? null)
        && hash_equals($expectedIssuer, $claims['iss'])
        && in_array($expectedAudience, $audiences, true)
        && is_int($expiresAt)
        && $expiresAt > time();
};

/** @return array{discovery: array<string, mixed>, jwks: array<string, mixed>} */
$loadProviderKeys = static function () use ($http, $config): array {
    $discoveryResponse = $http('GET', $config->providerIssuer . '/.well-known/openid-configuration', ['Accept: application/json']);
    $discovery = json_decode($discoveryResponse['body'], true);
    if ($discoveryResponse['status'] !== 200 || !is_array($discovery)
        || ($discovery['issuer'] ?? null) !== $config->providerIssuer
        || !is_string($discovery['jwks_uri'] ?? null)
        || !is_string($discovery['authorization_endpoint'] ?? null)
        || !is_string($discovery['token_endpoint'] ?? null)) {
        throw new RuntimeException('Provider discovery is invalid or unavailable over verified HTTPS.');
    }
    $jwksResponse = $http('GET', $discovery['jwks_uri'], ['Accept: application/json']);
    $jwks = json_decode($jwksResponse['body'], true);
    if ($jwksResponse['status'] !== 200 || !is_array($jwks) || !is_array($jwks['keys'] ?? null)) {
        throw new RuntimeException('Provider JWKS is invalid or unavailable.');
    }
    $seen = [];
    foreach ($jwks['keys'] as $key) {
        if (!is_array($key) || !is_string($key['kid'] ?? null) || $key['kid'] === '') {
            throw new RuntimeException('JWKS contains a malformed key entry.');
        }
        if (isset($seen[$key['kid']])) {
            throw new RuntimeException('JWKS contains duplicate key IDs.');
        }
        $seen[$key['kid']] = true;
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as $privateParameter) {
            if (array_key_exists($privateParameter, $key)) {
                throw new RuntimeException('JWKS exposes a private RSA key parameter.');
            }
        }
    }

    return ['discovery' => $discovery, 'jwks' => $jwks];
};

/** @return array{code: string, verifier: string} */
$createAuthorizationCode = static function (string $authorizationEndpoint) use ($http, $config, $username, $password): array {
    $base64Url = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    $verifier = $base64Url(random_bytes(32));
    $challenge = $base64Url(hash('sha256', $verifier, true));
    $query = http_build_query([
        'client_id' => $config->clientId,
        'response_type' => 'code',
        'redirect_uri' => $config->redirectUri,
        'scope' => 'openid profile email',
        'state' => bin2hex(random_bytes(16)),
        'nonce' => bin2hex(random_bytes(16)),
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ], '', '&', PHP_QUERY_RFC3986);
    $page = $http('GET', $authorizationEndpoint . '?' . $query, ['Accept: text/html']);
    if ($page['status'] !== 200 || !preg_match('/name="csrf_token"\s+value="([a-f0-9]+)"/i', $page['body'], $match)
        || !isset($page['headers']['set-cookie'])) {
        throw new RuntimeException('Unable to initialize provider login form.');
    }
    $cookie = explode(';', $page['headers']['set-cookie'], 2)[0];
    $login = $http('POST', $authorizationEndpoint, [
        'Accept: text/html',
        'Content-Type: application/x-www-form-urlencoded',
        'Cookie: ' . $cookie,
    ], http_build_query([
        'csrf_token' => $match[1],
        'username' => $username,
        'password' => $password,
        'approve' => '1',
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

/** @return array<string, mixed> */
$redeem = static function (array $transaction, string $tokenEndpoint) use ($http, $config): array {
    $headers = [
        'Accept: application/json',
        'Content-Type: application/x-www-form-urlencoded',
        'Authorization: Basic ' . base64_encode($config->clientId . ':' . $config->clientSecret),
    ];
    $response = $http('POST', $tokenEndpoint, $headers, http_build_query([
        'grant_type' => 'authorization_code',
        'code' => $transaction['code'],
        'redirect_uri' => $config->redirectUri,
        'code_verifier' => $transaction['verifier'],
    ], '', '&', PHP_QUERY_RFC3986));
    $payload = json_decode($response['body'], true);
    if ($response['status'] !== 200 || !is_array($payload) || !is_string($payload['id_token'] ?? null)) {
        throw new RuntimeException('Authorization-code exchange did not return a valid ID Token.');
    }

    return $payload;
};

$stateDirectory = __DIR__ . '/../var';
$statePath = $stateDirectory . '/key-rotation-state.json';
$checks = [];
$record = static function (string $name, bool $passed, string $detail) use (&$checks): void {
    $checks[] = ['name' => $name, 'passed' => $passed, 'detail' => $detail];
};

try {
    if ($mode === 'prepare') {
        $provider = $loadProviderKeys();
        $published = $provider['jwks']['keys'];
        $activeKid = is_array($published[0] ?? null) ? ($published[0]['kid'] ?? null) : null;
        $record('Provider currently publishes the expected old key as active', is_string($activeKid) && hash_equals($oldKid, $activeKid), 'expected old kid ' . $oldKid . '; active kid ' . (is_string($activeKid) ? $activeKid : 'missing'));
        if (!is_string($activeKid) || !hash_equals($oldKid, $activeKid)) {
            throw new RuntimeException('The provider is not currently using the configured old signing key; do not prepare against an unexpected key.');
        }

        $transaction = $createAuthorizationCode($provider['discovery']['authorization_endpoint']);
        $tokens = $redeem($transaction, $provider['discovery']['token_endpoint']);
        $jwt = $parseJwt($tokens['id_token']);
        $tokenKid = $jwt['header']['kid'];
        $signatureValid = is_string($tokenKid) && hash_equals($oldKid, $tokenKid)
            && $verifyJwt($jwt, $provider['jwks'], $config->providerIssuer, $config->clientId);
        $record('Pre-rotation ID Token is signed by the old key and validates against current JWKS', $signatureValid, 'issued kid ' . (is_string($tokenKid) ? $tokenKid : 'missing'));
        if (!$signatureValid) {
            throw new RuntimeException('The pre-rotation ID Token could not be verified with the old JWKS.');
        }

        if (!is_dir($stateDirectory) && !mkdir($stateDirectory, 0700, true) && !is_dir($stateDirectory)) {
            throw new RuntimeException('Unable to create the interop-client/var state directory.');
        }
        $state = [
            'issuer' => $config->providerIssuer,
            'client_id' => $config->clientId,
            'old_kid' => $oldKid,
            'id_token' => $tokens['id_token'],
            'expires_at' => $jwt['claims']['exp'] ?? null,
            'prepared_at' => time(),
        ];
        if (!is_int($state['expires_at']) || file_put_contents($statePath, json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
            throw new RuntimeException('Unable to persist the temporary pre-rotation ID Token state.');
        }
        @chmod($statePath, 0600);
        $record('Temporary pre-rotation token state saved locally', true, 'state file: interop-client/var/key-rotation-state.json; expires at ' . gmdate('c', $state['expires_at']));
    } else {
        if (!is_file($statePath)) {
            throw new RuntimeException('No pre-rotation state found. Run composer security-checks:rotation:prepare before changing the provider key.');
        }
        $state = json_decode((string) file_get_contents($statePath), true);
        if (!is_array($state) || ($state['issuer'] ?? null) !== $config->providerIssuer
            || ($state['client_id'] ?? null) !== $config->clientId
            || ($state['old_kid'] ?? null) !== $oldKid
            || !is_string($state['id_token'] ?? null)) {
            throw new RuntimeException('The saved pre-rotation state does not match the configured issuer, client or old key ID.');
        }
        if (!is_int($state['expires_at'] ?? null) || $state['expires_at'] <= time()) {
            throw new RuntimeException('The saved pre-rotation ID Token has expired. Run prepare again with the old key active, then rotate and verify before its expiry.');
        }

        $provider = $loadProviderKeys();
        $published = $provider['jwks']['keys'];
        $activeKid = is_array($published[0] ?? null) ? ($published[0]['kid'] ?? null) : null;
        $newJwk = $findJwk($provider['jwks'], $newKid);
        $oldJwk = $findJwk($provider['jwks'], $oldKid);
        $record('Provider publishes the new key as active', is_string($activeKid) && hash_equals($newKid, $activeKid), 'expected new kid ' . $newKid . '; active kid ' . (is_string($activeKid) ? $activeKid : 'missing'));
        $record('JWKS retains the old public key during the overlap period', $oldJwk !== null, 'old kid ' . $oldKid . ' present: ' . ($oldJwk !== null ? 'yes' : 'no'));
        $record('JWKS publishes the new public key', $newJwk !== null, 'new kid ' . $newKid . ' present: ' . ($newJwk !== null ? 'yes' : 'no'));
        if (!is_string($activeKid) || !hash_equals($newKid, $activeKid) || $oldJwk === null || $newJwk === null) {
            throw new RuntimeException('The rotated JWKS does not contain the expected active and retired keys.');
        }

        $oldJwt = $parseJwt($state['id_token']);
        $oldValid = ($oldJwt['header']['kid'] ?? null) === $oldKid
            && $verifyJwt($oldJwt, $provider['jwks'], $config->providerIssuer, $config->clientId);
        $record('Previously issued ID Token remains verifiable with the rotated JWKS', $oldValid, 'old token kid ' . $oldKid . '; token still unexpired: yes');

        $transaction = $createAuthorizationCode($provider['discovery']['authorization_endpoint']);
        $tokens = $redeem($transaction, $provider['discovery']['token_endpoint']);
        $newJwt = $parseJwt($tokens['id_token']);
        $issuedKid = $newJwt['header']['kid'] ?? null;
        $newValid = is_string($issuedKid) && hash_equals($newKid, $issuedKid)
            && $verifyJwt($newJwt, $provider['jwks'], $config->providerIssuer, $config->clientId);
        $record('New authorization flow issues an ID Token signed by the new key', $newValid, 'expected kid ' . $newKid . '; issued kid ' . (is_string($issuedKid) ? $issuedKid : 'missing'));

        if ($oldValid && $newValid) {
            if (!unlink($statePath)) {
                fwrite(STDERR, "WARNING: rotation state could not be deleted; remove interop-client/var/key-rotation-state.json manually.\n");
            }
        }
    }
} catch (Throwable $exception) {
    fwrite(STDERR, 'Key-rotation checks could not complete: ' . $exception->getMessage() . "\n");
    exit(2);
}

$passed = count(array_filter($checks, static fn (array $check): bool => $check['passed']));
foreach ($checks as $check) {
    printf("%s %s — %s\n", $check['passed'] ? 'PASS' : 'FAIL', $check['name'], $check['detail']);
}
printf("\n%d/%d key-rotation checks passed (%s).\n", $passed, count($checks), $mode);
exit($passed === count($checks) ? 0 : 1);

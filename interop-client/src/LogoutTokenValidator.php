<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient;

use RuntimeException;

final readonly class LogoutTokenValidator
{
    /** @param array<string, string> $keysById */
    public function __construct(
        private string $issuer,
        private string $clientId,
        private array $keysById,
        private LogoutTokenStore $replayStore,
    ) {
    }

    /** @return array{sub?:string,sid?:string} */
    public function validate(string $jwt): array
    {
        if ($jwt === '' || strlen($jwt) > 8192) {
            throw new RuntimeException('Logout Token length is invalid.');
        }
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed Logout Token.');
        }
        $decode = static function (string $part): string {
            $decoded = base64_decode(strtr($part, '-_', '+/') . str_repeat('=', (4 - strlen($part) % 4) % 4), true);
            if (!is_string($decoded)) {
                throw new RuntimeException('Malformed Logout Token encoding.');
            }
            return $decoded;
        };
        $header = json_decode($decode($parts[0]));
        $claims = json_decode($decode($parts[1]));
        $signature = $decode($parts[2]);
        if (!$header instanceof \stdClass || !$claims instanceof \stdClass
            || ($header->alg ?? null) !== 'RS256' || ($header->typ ?? null) !== 'logout+jwt'
            || !is_string($header->kid ?? null) || !isset($this->keysById[$header->kid])
            || openssl_verify($parts[0] . '.' . $parts[1], $signature, $this->keysById[$header->kid], OPENSSL_ALGO_SHA256) !== 1) {
            throw new RuntimeException('Logout Token signature or header is invalid.');
        }
        $audiences = is_array($claims->aud ?? null) ? $claims->aud : [$claims->aud ?? null];
        $events = $claims->events ?? null;
        $eventName = 'http://schemas.openid.net/event/backchannel-logout';
        $now = time();
        $issuedAt = $claims->iat ?? null;
        $expiresAt = $claims->exp ?? null;
        $validNumericDate = static fn (mixed $value): bool => (is_int($value) || is_float($value))
            && is_finite((float) $value);
        if (($claims->iss ?? null) !== $this->issuer || !in_array($this->clientId, $audiences, true)
            || !$validNumericDate($issuedAt) || $issuedAt > $now + 60
            || !$validNumericDate($expiresAt) || $expiresAt <= $now || $expiresAt <= $issuedAt
            || !is_string($claims->jti ?? null) || $claims->jti === '' || strlen($claims->jti) > 255 || isset($claims->nonce)
            || (isset($claims->sub) && (!is_string($claims->sub) || $claims->sub === '' || strlen($claims->sub) > 255))
            || (isset($claims->sid) && (!is_string($claims->sid) || $claims->sid === '' || strlen($claims->sid) > 255))
            || ((!is_string($claims->sub ?? null) || $claims->sub === '')
                && (!is_string($claims->sid ?? null) || $claims->sid === ''))
            || !$events instanceof \stdClass || !isset($events->$eventName) || !$events->$eventName instanceof \stdClass) {
            throw new RuntimeException('Logout Token claims are invalid.');
        }
        if (!$this->replayStore->claim($this->issuer, $this->clientId, $claims->jti, (int) ceil($expiresAt))) {
            throw new RuntimeException('Logout Token replay detected.');
        }
        $result = [];
        if (is_string($claims->sub ?? null)) {
            $result['sub'] = $claims->sub;
        }
        if (is_string($claims->sid ?? null)) {
            $result['sid'] = $claims->sid;
        }
        return $result;
    }
}

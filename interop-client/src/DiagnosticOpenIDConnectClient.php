<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient;

use Jumbojett\OpenIDConnectClient;

/**
 * Adds non-sensitive claim-validation diagnostics for the local interoperability harness.
 * It preserves the upstream client's validation result and never exposes token or nonce values.
 */
final class DiagnosticOpenIDConnectClient extends OpenIDConnectClient
{
    /** @var array<string, bool|int|string|null> */
    private array $claimValidationDiagnostics = [];

    /** @return array<string, bool|int|string|null> */
    public function claimValidationDiagnostics(): array
    {
        return $this->claimValidationDiagnostics;
    }

    protected function verifyJWTClaims($claims, ?string $accessToken = null): bool
    {
        $issuer = $claims->iss ?? null;
        $audience = $claims->aud ?? null;
        $audiences = is_array($audience) ? $audience : [$audience];
        $subject = $claims->sub ?? null;
        $nonce = $claims->nonce ?? null;
        $expiresAt = $claims->exp ?? null;
        $notBefore = $claims->nbf ?? null;
        $issuedAt = $claims->iat ?? null;
        $expectedNonce = $this->getNonce();
        $decodedPayload = $this->getIdTokenPayload();

        $this->claimValidationDiagnostics = [
            'issuer_present' => is_string($issuer),
            'issuer_matches_configured_provider' => is_string($issuer) && $this->validateIssuer($issuer),
            'audience_contains_client_id' => in_array($this->getClientID(), $audiences, true),
            'subject_present' => is_string($subject) && $subject !== '',
            'subject_matches_decoded_token' => is_object($decodedPayload)
                && is_string($subject)
                && isset($decodedPayload->sub)
                && $subject === $decodedPayload->sub,
            'nonce_present' => is_string($nonce) && $nonce !== '',
            'nonce_matches_login_session' => is_string($nonce)
                && hash_equals($expectedNonce, $nonce),
            'expiration_valid' => !isset($expiresAt)
                || (is_int($expiresAt) && $expiresAt >= time() - $this->getLeeway()),
            'expiration_claim_type' => get_debug_type($expiresAt),
            'expiration_is_integer' => is_int($expiresAt),
            'expiration_seconds_remaining' => is_int($expiresAt) ? $expiresAt - time() : null,
            'client_clock_unix' => time(),
            'client_leeway_seconds' => $this->getLeeway(),
            'issued_at_claim_type' => get_debug_type($issuedAt),
            'issued_at_seconds_ago' => is_int($issuedAt) ? time() - $issuedAt : null,
            'not_before_valid' => !isset($notBefore)
                || (is_int($notBefore) && $notBefore <= time() + $this->getLeeway()),
        ];

        return parent::verifyJWTClaims($claims, $accessToken);
    }
}

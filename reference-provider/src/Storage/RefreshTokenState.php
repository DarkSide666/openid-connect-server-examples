<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Storage;

use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use DarkSide\OpenIdConnectServer\League\RefreshTokenConsumptionResult;

final readonly class RefreshTokenState
{
    private FileState $state;

    public function __construct(string $path)
    {
        $this->state = new FileState($path);
    }

    /** @param array<string, mixed> $token */
    public function create(string $tokenId, array $token, string $familyId): void
    {
        $this->state->update(static function (array &$state) use ($tokenId, $token, $familyId): void {
            $tokens = $state['tokens'] ?? [];
            if (!is_array($tokens) || isset($tokens[$tokenId])) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }
            $revokedFamilies = $state['revoked_families'] ?? [];
            $familyRevoked = is_array($revokedFamilies) && ($revokedFamilies[$familyId] ?? false) === true;
            $tokens[$tokenId] = $token + ['family_id' => $familyId, 'revoked' => $familyRevoked];
            $state['tokens'] = $tokens;
        });
    }

    public function family(string $tokenId): ?string
    {
        $tokens = $this->tokens();
        $familyId = $tokens[$tokenId]['family_id'] ?? null;
        return is_string($familyId) ? $familyId : null;
    }

    public function revoke(string $tokenId): void
    {
        $this->state->update(static function (array &$state) use ($tokenId): void {
            $tokens = $state['tokens'] ?? [];
            if (is_array($tokens) && isset($tokens[$tokenId]) && is_array($tokens[$tokenId])) {
                $tokens[$tokenId]['revoked'] = true;
                $state['tokens'] = $tokens;
            }
        });
    }

    public function isRevoked(string $tokenId): bool
    {
        $tokens = $this->tokens();
        return !isset($tokens[$tokenId]) || ($tokens[$tokenId]['revoked'] ?? true) !== false;
    }

    public function consume(string $tokenId): RefreshTokenConsumptionResult
    {
        return $this->state->update(static function (array &$state) use ($tokenId): RefreshTokenConsumptionResult {
            $tokens = $state['tokens'] ?? [];
            if (!is_array($tokens) || !is_array($tokens[$tokenId] ?? null)) {
                return RefreshTokenConsumptionResult::INVALID;
            }
            if (($tokens[$tokenId]['consumed'] ?? false) === true) {
                return RefreshTokenConsumptionResult::REPLAYED;
            }
            if (($tokens[$tokenId]['revoked'] ?? true) !== false
                || !is_int($tokens[$tokenId]['expires_at'] ?? null)
                || $tokens[$tokenId]['expires_at'] < time()) {
                return RefreshTokenConsumptionResult::INVALID;
            }
            $tokens[$tokenId]['revoked'] = true;
            $tokens[$tokenId]['consumed'] = true;
            $state['tokens'] = $tokens;
            return RefreshTokenConsumptionResult::CONSUMED;
        });
    }

    public function revokeFamily(string $tokenId): void
    {
        $this->state->update(static function (array &$state) use ($tokenId): void {
            $tokens = $state['tokens'] ?? [];
            if (!is_array($tokens)) {
                return;
            }
            $familyId = is_array($tokens[$tokenId] ?? null) ? ($tokens[$tokenId]['family_id'] ?? null) : null;
            if (!is_string($familyId) || ($tokens[$tokenId]['consumed'] ?? false) !== true) {
                return;
            }
            $revokedFamilies = $state['revoked_families'] ?? [];
            if (!is_array($revokedFamilies)) {
                $revokedFamilies = [];
            }
            $revokedFamilies[$familyId] = true;
            $state['revoked_families'] = $revokedFamilies;
            foreach ($tokens as &$token) {
                if (is_array($token) && ($token['family_id'] ?? null) === $familyId) {
                    $token['revoked'] = true;
                }
            }
            unset($token);
            $state['tokens'] = $tokens;
        });
    }

    /** @return array<string, array<string, mixed>> */
    private function tokens(): array
    {
        $tokens = $this->state->read()['tokens'] ?? [];
        return is_array($tokens) ? $tokens : [];
    }
}

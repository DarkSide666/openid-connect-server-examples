<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient\Tests;

use PHPUnit\Framework\TestCase;

final class SecurityProbeDocumentationTest extends TestCase
{
    public function testSecurityProbeDocumentsTheExpectedNegativeScenarios(): void
    {
        $script = file_get_contents(dirname(__DIR__) . '/bin/security-checks.php');

        self::assertIsString($script);
        self::assertStringContainsString('deliberately-incorrect-secret', $script);
        self::assertStringContainsString('security-probe-invalid-code', $script);
        self::assertStringContainsString("'grant_type' => 'refresh_token'", $script);
        self::assertStringContainsString('Authorization: Bearer not-a-valid-access-token', $script);
    }
}

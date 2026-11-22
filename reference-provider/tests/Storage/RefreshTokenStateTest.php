<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Tests\Storage;

use DarkSide\OpenIdConnectServer\League\RefreshTokenConsumptionResult;
use DarkSide\OidcReferenceProvider\Storage\RefreshTokenState;
use PHPUnit\Framework\TestCase;

final class RefreshTokenStateTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/darkside-refresh-token-' . bin2hex(random_bytes(8)) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testReuseRevokesExistingAndInFlightFamilyTokens(): void
    {
        $state = new RefreshTokenState($this->path);
        $state->create('first', ['expires_at' => time() + 60], 'family-1');
        $state->create('replacement', ['expires_at' => time() + 120], 'family-1');

        self::assertSame(RefreshTokenConsumptionResult::CONSUMED, $state->consume('first'));
        self::assertSame(RefreshTokenConsumptionResult::REPLAYED, $state->consume('first'));
        $state->revokeFamily('first');
        // This is the interleaving where a concurrent request already consumed
        // the original token but persists its replacement after replay handling.
        $state->create('late-replacement', ['expires_at' => time() + 180], 'family-1');

        self::assertTrue($state->isRevoked('first'));
        self::assertTrue($state->isRevoked('replacement'));
        self::assertTrue($state->isRevoked('late-replacement'));
    }

    public function testConcurrentConsumersCannotBothConsumeTheSameToken(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('Concurrent refresh-token test requires proc_open.');
        }

        $state = new RefreshTokenState($this->path);
        $state->create('first', ['expires_at' => time() + 60], 'family-1');
        $barrierDirectory = sys_get_temp_dir() . '/darkside-refresh-race-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($barrierDirectory, 0700));
        $goFile = $barrierDirectory . '/go';
        $workerScript = dirname(__DIR__) . '/Support/RefreshTokenStateWorker.php';
        /** @var list<array{process: resource, pipes: array{0: resource, 1: resource, 2: resource}}> $workers */
        $workers = [];

        try {
            for ($workerId = 1; $workerId <= 2; $workerId++) {
                $pipes = [];
                $process = proc_open(
                    [PHP_BINARY, $workerScript, $this->path, $barrierDirectory, (string) $workerId],
                    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                    $pipes,
                );
                self::assertIsResource($process);
                fclose($pipes[0]);
                $workers[] = ['process' => $process, 'pipes' => $pipes];
            }

            $readyDeadline = microtime(true) + 10;
            while (!is_file($barrierDirectory . '/ready-1') || !is_file($barrierDirectory . '/ready-2')) {
                if (microtime(true) >= $readyDeadline) {
                    break;
                }
                usleep(1000);
            }
            self::assertTrue(touch($goFile));

            $results = [];
            foreach ($workers as $worker) {
                $results[] = trim((string) stream_get_contents($worker['pipes'][1]));
                $errorOutput = (string) stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                self::assertSame('', $errorOutput);
                self::assertSame(0, proc_close($worker['process']));
            }

            self::assertFileExists($barrierDirectory . '/ready-1');
            self::assertFileExists($barrierDirectory . '/ready-2');
            self::assertEqualsCanonicalizing(['CONSUMED', 'REPLAYED'], $results);
        } finally {
            if (!is_file($goFile)) {
                touch($goFile);
            }
            foreach ($workers as $worker) {
                foreach ([1, 2] as $pipeIndex) {
                    if (is_resource($worker['pipes'][$pipeIndex])) {
                        fclose($worker['pipes'][$pipeIndex]);
                    }
                }
                if (is_resource($worker['process'])) {
                    proc_terminate($worker['process']);
                    proc_close($worker['process']);
                }
            }
            foreach (glob($barrierDirectory . '/*') ?: [] as $barrierFile) {
                unlink($barrierFile);
            }
            rmdir($barrierDirectory);
        }
    }

    public function testUnknownAndExpiredTokensCannotBeConsumed(): void
    {
        $state = new RefreshTokenState($this->path);
        $state->create('expired', ['expires_at' => time() - 1], 'family-2');

        self::assertSame(RefreshTokenConsumptionResult::INVALID, $state->consume('missing'));
        self::assertSame(RefreshTokenConsumptionResult::INVALID, $state->consume('expired'));
    }
}

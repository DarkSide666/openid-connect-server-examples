<?php

declare(strict_types=1);

use DarkSide\OpenIdConnectServer\League\RefreshTokenConsumptionResult;
use DarkSide\OidcReferenceProvider\Storage\RefreshTokenState;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

[$script, $statePath, $barrierDirectory, $workerId] = $argv;
$state = new RefreshTokenState($statePath);
file_put_contents($barrierDirectory . '/ready-' . $workerId, 'ready', LOCK_EX);
$deadline = microtime(true) + 10;
while (!is_file($barrierDirectory . '/go')) {
    if (microtime(true) >= $deadline) {
        fwrite(STDERR, 'Timed out waiting for the concurrent-consumption barrier.');
        exit(1);
    }
    usleep(1000);
}

$result = $state->consume('first');
if (!$result instanceof RefreshTokenConsumptionResult) {
    fwrite(STDERR, 'The refresh-token store returned an unexpected result.');
    exit(1);
}
echo $result->name;

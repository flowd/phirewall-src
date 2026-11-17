<?php

declare(strict_types=1);

use Tally\Configuration;

// Tally counts instructions, cycles and memory instead of time: see CONTRIBUTING.md.
return Configuration::create()
    ->withPaths([__DIR__ . '/benchmarks'])
    ->withIniEntries([
        'memory_limit=-1',
        'zend.assertions=-1',
        // The "per request" cases stand for PHP-FPM, where code and compiled data come
        // from OPcache. Without it, a cached artifact is compiled on every request and
        // looks more expensive than no cache at all.
        'opcache.enable=1',
        'opcache.enable_cli=1',
        'opcache.jit=disable',
        // OPcache does not cache a file written within the last two seconds by default,
        // which is exactly what a benchmark does with its artifacts.
        'opcache.file_update_protection=0',
    ]);

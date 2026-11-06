<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\Catch_\ThrowWithPreviousExceptionRector;
use Rector\CodingStyle\Rector\Encapsed\EncapsedStringsToSprintfRector;
use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\Cast\RecastingRemovalRector;
use Rector\Naming\Rector\Assign\RenameVariableToMatchMethodCallReturnTypeRector;
use Rector\Naming\Rector\Class_\RenamePropertyToMatchTypeRector;
use Rector\Naming\Rector\ClassMethod\RenameVariableToMatchNewTypeRector;
use Rector\Php55\Rector\String_\StringClassNameToClassConstantRector;
use Rector\PHPUnit\PHPUnit60\Rector\ClassMethod\AddDoesNotPerformAssertionToNonAssertingTestRector;

return RectorConfig::configure()
    ->withPaths(array_merge(
        glob(__DIR__ . '/packages/*/examples', GLOB_ONLYDIR) ?: [],
        glob(__DIR__ . '/packages/*/src', GLOB_ONLYDIR) ?: [],
        glob(__DIR__ . '/packages/*/tests', GLOB_ONLYDIR) ?: [],
    ))
    ->withPhpSets(php82: true)
    ->withPHPStanConfigs([
        __DIR__ . '/phpstan.neon.dist',
    ])
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        codingStyle: true,
        typeDeclarations: true,
        privatization: true,
        naming: true,
        instanceOf: true,
        earlyReturn: true,
        strictBooleans: true,
        rectorPreset: true,
        phpunitCodeQuality: true,
        phpunit: true,
    )
    ->withSkip([
        StringClassNameToClassConstantRector::class => [
            __DIR__ . '/packages/phirewall/src/Http/ResponseFactoryResolver.php',
        ],
        RenamePropertyToMatchTypeRector::class,
        RenameVariableToMatchMethodCallReturnTypeRector::class,
        RenameVariableToMatchNewTypeRector::class,
        RecastingRemovalRector::class,
        EncapsedStringsToSprintfRector::class,
        AddDoesNotPerformAssertionToNonAssertingTestRector::class,
        // The core only skips it for PdoCache, the extensions skip it everywhere.
        ThrowWithPreviousExceptionRector::class => [
            __DIR__ . '/packages/phirewall/src/Store/PdoCache.php',
            __DIR__ . '/packages/phirewall-preset-*',
        ],
    ]);

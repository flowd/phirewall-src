<?php

declare(strict_types=1);

use Symplify\MonorepoBuilder\Config\MBConfig;

return static function (MBConfig $mbConfig): void {
    $mbConfig->packageDirectories([__DIR__ . '/packages']);
    $mbConfig->defaultBranch('main');

    // Branch alias of dev-main, e.g. 0.11.x-dev (applied by `package-alias`).
    $mbConfig->packageAliasFormat('<major>.<minor>.x-dev');

    // The extensions run against the core from this repository, so they must not be
    // installed from Packagist: the root composer.json replaces every package.
    $mbConfig->dataToAppend([
        'require-dev' => [
            'friendsofphp/php-cs-fixer' => '^3.89',
            'infection/infection' => '^0.29',
            'phpstan/phpstan' => '^1.12',
            'rector/rector' => '^1.2',
            'symplify/monorepo-builder' => '^12.7',
        ],
        'config' => [
            'sort-packages' => true,
            'allow-plugins' => [
                'infection/extension-installer' => false,
            ],
        ],
    ]);
};

# Contributing

Thank you for helping! All development happens in this repository, the package repositories
(`flowd/phirewall`, `flowd/phirewall-preset-*`) are read-only mirrors.

## Setup

```bash
composer install
composer test
```

See the [README](README.md#development) for the individual commands.

## Pull requests

- Branch off `main` and open the pull request against `main`.
- Keep a change inside one package where possible. A change of the core that affects the extensions
  needs the extensions to keep passing: CI runs all packages on PHP 8.2 to 8.5.
- Run `composer fix` before you push, `composer test` has to pass.
- Add a line under `## Unreleased` in the `CHANGELOG.md` of the package for user-visible changes.
  (`flowd/phirewall` has no such section yet, add one on top when you need it.)
- A package has to work on its own: CI installs every package standalone, with the lowest and the
  newest allowed dependencies, and checks for dependencies that are used but not declared.
  Declare what you use in the `composer.json` of that package, then run `composer monorepo:merge`.

## Releases

Maintainers only, see the Releases section of the [README](README.md#releases).

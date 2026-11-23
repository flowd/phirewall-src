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
  needs the extensions to keep passing: CI runs all packages on PHP 8.2 to 8.6.
- Run `composer fix` before you push, `composer test` has to pass.
- Add a line under `## Unreleased` in the `CHANGELOG.md` of the package for user-visible changes.
  (`flowd/phirewall` has no such section yet, add one on top when you need it.)
- A package has to work on its own: CI installs every package standalone, with the lowest and the
  newest allowed dependencies, and checks for dependencies that are used but not declared.
  Declare what you use in the `composer.json` of that package, then run `composer monorepo:merge`.

## Benchmarks

`benchmarks/` holds [Tally](https://github.com/phpstan/tally) benchmarks. Tally runs each one once under
a CPU simulation and counts instructions, cycles and memory instead of measuring time, so the numbers are
the same on every run and are committed next to the benchmark, like the expected output of a test. CI
fails when a benchmark does more work than its numbers allow (±2 % of the instructions by default).

```bash
composer benchmarks                                       # Linux on x86_64 or aarch64 only
vendor/bin/tally run --filter=CrsPresetBench::benchPageViewInAWorker
```

- **Take the numbers from CI.** They depend on the PHP build and the system libraries, so a run on your
  machine reports most benchmarks as slower or faster. Locally, compare a run before with a run after
  your change (`vendor/bin/tally run --output=<directory>`, then `vendor/bin/tally compare --table <directory>`).
- **Your change makes a benchmark faster or slower on purpose:** the summary of the `Benchmarks` job
  ends with the commands that download its results and write the new numbers into the benchmark
  (`gh run download ...`, then `vendor/bin/tally accept ...`). Commit the result with your change, and say
  in the pull request why a number went up.
- **A new benchmark** needs no numbers: it does not fail, and the job summary ends with a patch that
  adds them.
- **An update of the CRS rules, of PHP or of the runner image** moves many numbers at once. Accept them
  in the pull request of the update.

A benchmark is named after what it stands for. "In a worker" counts one decision of a firewall that
already exists (RoadRunner, FrankenPHP, Swoole). "Per request" builds the configuration and the firewall
too and forgets what the previous request left in the process, as PHP-FPM does; these cases need OPcache,
which `tally.php` switches on. Every benchmark class checks in its `#[Before]` hook that its request ends
the way its name says.

## Releases

Maintainers only, see the Releases section of the [README](README.md#releases).

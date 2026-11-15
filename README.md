<img src="packages/phirewall/docs/assets/logo.svg" width="200" alt="Phirewall Logo" align="right">

# Phirewall

**Protect your PHP application from brute force, DDoS, SQL injection, XSS, and bot attacks with a single middleware.**

**[Phirewall](https://phirewall.de)** is a PSR-15 middleware that provides application-layer protection. It is
lightweight, framework-agnostic, and easy to configure. This repository is the home of Phirewall and its
optional extensions: everything is developed, tested, and released from here.

---

## Packages

| Package | Install | What it does |
| --- | --- | --- |
| [**flowd/phirewall**](packages/phirewall) | `composer require flowd/phirewall` | The firewall: safelists, blocklists, throttling, Fail2Ban, Allow2Ban, tracking, PSR-14 events |
| [**flowd/phirewall-preset-owasp-crs**](packages/phirewall-preset-owasp-crs) | `composer require flowd/phirewall-preset-owasp-crs` | OWASP Core Rule Set: SQL injection, XSS, and more |
| [**flowd/phirewall-preset-bots**](packages/phirewall-preset-bots) | `composer require flowd/phirewall-preset-bots` | Block AI crawlers, rate-limit aggressive SEO crawlers |
| [**flowd/phirewall-preset-bad-ips**](packages/phirewall-preset-bad-ips) | `composer require flowd/phirewall-preset-bad-ips` | Threat-intelligence IP blocklist |

The extensions are optional, independent of each other, and require the core (`flowd/phirewall`).
All four packages are released together and share one version.

## Quick Start

```bash
composer require flowd/phirewall
```

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Store\InMemoryCache;

$config = new Config(new InMemoryCache());

// Rate limit: 100 requests per minute per IP
$config->throttles->add('api', limit: 100, period: 60);

// Add it to your PSR-15 pipeline
$middleware = new Middleware($config);
```

More in the [package README](packages/phirewall/README.md), the runnable
[examples](packages/phirewall/examples), and the [documentation](https://phirewall.de):

- [Getting Started](https://phirewall.de/getting-started.html)
- [Framework Integration](https://phirewall.de/examples.html): Laravel, Symfony, Slim, Mezzio, and more
- [Common Attacks](https://phirewall.de/common-attacks.html): protection recipes
- [FAQ](https://phirewall.de/faq.html)

---

## Repository

> [!NOTE]
> `flowd/phirewall` and the `flowd/phirewall-preset-*` repositories are **read-only mirrors** of
> `packages/<name>` in this repository. They are overwritten on every release so that Packagist can serve
> each package on its own. **Please open issues and pull requests here.**

```
packages/                   one directory per Composer package (src, tests, examples, composer.json, ...)
docs-site/                  documentation site (VitePress, pnpm)
bin/release                 prepares a release and opens the release pull request
bin/monorepo-merge          regenerates the root composer.json from the packages
.github/workflows/          CI, scheduled updates, release and split
composer.json               root package: replaces all packages, holds the shared dev tools
monorepo-builder.php        configuration of symplify/monorepo-builder
```

The root `composer.json` is generated. Change the package `composer.json` files and run
`composer monorepo:merge` instead of editing its dependencies by hand.

## Development

```bash
composer install            # one install for all packages
composer test               # monorepo validation, Rector, PHP-CS-Fixer, PHPStan, PHPUnit
```

| Command | Purpose |
| --- | --- |
| `composer phpunit` | PHPUnit of every package |
| `composer phpunit:core`, `phpunit:owasp-crs`, `phpunit:bots`, `phpunit:bad-ips` | PHPUnit of one package |
| `composer phpstan` | PHPStan (level max) over all packages |
| `composer cs:check` / `composer cs:fix` | PHP-CS-Fixer |
| `composer rector:check` / `composer rector:fix` | Rector |
| `composer fix` | Rector and PHP-CS-Fixer, applying the changes |
| `composer monorepo:merge` / `composer monorepo:validate` | Root `composer.json` and consistency of the packages |
| `composer test:database` | `PdoCache` against SQLite, MySQL and PostgreSQL (needs Docker) |

Rector, PHP-CS-Fixer and PHPStan are configured once at the root (`rector.php`, `.php-cs-fixer.php`,
`phpstan.neon.dist`). PHPUnit runs per package with the `phpunit.xml.dist` of that package.

Examples and the Infection run expect `vendor/` inside the package. To run one locally, link the root
directory temporarily: `ln -s ../../vendor packages/<package>/vendor` (the CI does the same, never commit it).

Docs: `cd docs-site && pnpm install && pnpm dev`, or use `docs-site/compose.yaml`.

## Releases

All packages share one version and one git tag per release (`0.11.0`, no `v` prefix). A release tags the
state of the whole family, an unchanged package gets the new tag as well. The version is only ever raised by
the release pull request.

```bash
bin/release minor --dry-run   # which packages changed since the last tag, which version
bin/release minor             # or: patch | X.Y.Z
```

`bin/release` must run on an up-to-date, clean `main` and needs `vendor/` (`composer install`) and `gh`. It
creates `release/X.Y.Z` with one commit that

- sets the constraint between the packages to `>=X.Y <1.0` (`<2.0` from 1.0.0 on, with `bin/release 1.0.0`),
- moves the `dev-main` branch alias of all packages to the next minor (`X.(Y+1).x-dev`),
- renames `## Unreleased` in each `CHANGELOG.md` to `## X.Y.Z - <date>`,
- regenerates the root `composer.json` and validates the packages,

then pushes the branch and opens the pull request with a table of what changed per package (informational
only). `bin/release --no-push` stops after the commit. The first release needs an explicit version, and
`major` is refused below 1.0.0.

Merging the pull request (any merge method) runs `.github/workflows/release.yml`:

1. finds the pull request of the pushed commit: it must be merged into `main`, have the pushed commit as its
   merge commit and come from a `release/X.Y.Z` branch of this repository. A pull request from a fork never
   releases, whatever its branch is called, and neither does a commit message on its own,
2. checks that the `dev-main` branch alias of all packages is `X.(Y+1).x-dev`, as `bin/release` sets it, and
   tags the merge commit `X.Y.Z`,
3. calls `split.yml`, which pushes every `packages/<name>` as a snapshot commit plus the tag to its mirror,
4. creates the GitHub release with generated notes.

Packagist picks the new tag up from the mirrors. The mirrors only receive release tags, so Packagist offers
released versions but no `dev-main`.

**Constraints between the packages.** The extensions require the core as `>=X.Y <1.0`. A release raises the
lower bound to the released minor, so every release of an extension needs the core of the same minor.
`monorepo-builder validate` (part of `composer test`) enforces consistent constraints.

**If the split fails half way.** The four jobs are independent. A job pushes the snapshot commit, then the
tag. If a job fails after the push, "Re-run failed jobs" fails again with `tag already exists` in that
mirror: delete the tag in the mirror (the GitHub App may bypass the tag ruleset) and re-run only that job.

**Rehearsing the split.** `split.yml` can be started by hand (Actions > Split > Run workflow). A manual run
writes to the test repositories `flowd/phirewall-test-1` to `-4` (core, owasp-crs, bots, bad-ips) and never
to the mirrors. Each test repository needs one initial commit, because the split action cannot push into a
completely empty repository. Run it with a throw-away tag (`0.0.1-test`) and `ref` `main`, check the content
and the tag, and delete the tags before the next run.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security issues as described in
[SECURITY.md](SECURITY.md), not in public issues.

## License

LGPL-3.0-or-later, see the `LICENSE` and `LICENSE.LGPL` files of each package.

# Phirewall Bad-IP Preset

Block requests from known malicious IP addresses with [flowd/phirewall](https://github.com/flowd/phirewall).

Ships a snapshot of the public-domain [stamparm/ipsum](https://github.com/stamparm/ipsum) threat feed and exposes it as a `PortableConfig` blocklist (a `ConfigLayer`), materialized with `Config::with()`.

## Installation

```bash
composer require flowd/phirewall-preset-bad-ips
```

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\PhirewallPresetBadIps\Presets;

$config = (new Config($cache))->with(Presets::blocklist());
```

| Preset | Effect |
| --- | --- |
| `Presets::blocklist()` | Blocks (403) requests whose client IP is in the bundled snapshot. |
| `Presets::track(period)` | Counts matches without blocking, to measure false positives before enforcing. |

## The bundled list

The snapshot comes from stamparm/ipsum `levels/3.txt` (addresses seen on at least three
source blacklists). ipsum is dedicated to the public domain under The Unlicense, which is why
it can be bundled here; see `resources/UPSTREAM-LICENSE`. `resources/manifest.json` records the
feed, level, address count and import time.

The repository ships a small placeholder sample. Populate the real list with:

```bash
bin/badip-import            # level 3 (default)
bin/badip-import --level=4  # tighter, fewer false positives
```

The scheduled `Bad-IP Update` workflow refreshes it and opens a pull request.

## Limits to be aware of

- **The list keys on the client IP from `REMOTE_ADDR`.** Behind a proxy or CDN that is the proxy
  address. Configure a trusted client-IP resolver on the `Config`, or the blocklist sees the
  proxy instead of the client.
- **A bundled snapshot goes stale** between refreshes, and IP reputation is never perfect: a
  shared host or CGNAT address can be listed for one offender. Prefer a higher level for fewer
  false positives, and consider `track()` first. Override the rule by name to combine with your
  own allowlist.
- ipsum is an aggregate of third-party lists; only the compiled artifact (what is bundled) is
  public domain.

## Development

```bash
composer install
composer test     # rector (dry-run), php-cs-fixer (dry-run), phpunit, phpstan
```

## License

LGPL-3.0-or-later (dual-licensed, proprietary licensing available), like flowd/phirewall. The
bundled IP data is public domain (The Unlicense) from stamparm/ipsum.

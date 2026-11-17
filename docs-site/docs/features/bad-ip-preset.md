---
outline: deep
---

# Bad-IP Blocklist Preset

Block requests from known malicious IP addresses. Shipped as the companion package
[`flowd/phirewall-preset-bad-ips`](https://github.com/flowd/phirewall-preset-bad-ips), which
bundles a public-domain snapshot of the [stamparm/ipsum](https://github.com/stamparm/ipsum)
threat feed and exposes it as a `PortableConfig` blocklist.

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
| `Presets::blocklist()` | Blocks requests whose client IP is in the bundled snapshot. |
| `Presets::track(period)` | Counts matches without blocking, to measure false positives first. |

The preset loads its ~18k-address snapshot lazily on the first request. Reading the list and turning it into a lookup table costs about 2 ms, under PHP-FPM on every request. Give the `Config` a compiled-data cache and the table comes ready from one OPcache-backed artifact, which leaves about 0.05 ms per request; the artifact is rebuilt when the data file changes:

```php
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetBadIps\Presets;

$config->setCompiledDataCache(new CompiledDataCache('/path/to/var/cache/phirewall'));
$config = $config->with(Presets::blocklist());
```

See [Presets › Caching expensive preset data](/advanced/presets#caching-expensive-preset-data) for the cache and [Performance › IP list cost](/advanced/performance#ip-list-cost) for how the figures were measured.

The artifact belongs to a data file of one modification time and size. A snapshot replaced by one with the same time and the same size is not noticed until the cache directory is cleared. That takes a deployment that gives every file one fixed time and keeps the cache directory; clear the directory on deployment if yours does.

## Updating the list

The snapshot is stamparm/ipsum `levels/3.txt` (addresses on at least three source blacklists),
public domain under The Unlicense. Refresh it with `bin/badip-import` (or the scheduled
`Bad-IP Update` workflow, which opens a pull request). A higher level means fewer false
positives:

```bash
bin/badip-import --level=4
```

## Limits

- **The blocklist matches the resolved client IP** (the `Config`'s IP resolver, falling back to
  `REMOTE_ADDR` when none is set). Behind a proxy or CDN, set the resolver once with
  `$config->setIpResolver((new \Flowd\Phirewall\Http\TrustedProxyResolver([...]))->resolve(...))` so it sees the real
  client, not the proxy.
- **A bundled snapshot goes stale** between refreshes, and a shared host or CGNAT address can be
  listed for one offender. Prefer a higher level, try `track()` first, and combine with your own
  allowlist by overriding the rule by name.

---
outline: deep
---

# Presets

Presets are ready-to-use rule bundles for recurring scenarios, so you don't have to hand-write the same rules each time. Each preset is a [`PortableConfig`](/advanced/portable-config) returned by an accessor (e.g. `Presets::scannerBlocking()`): plain, inspectable, serializable data you can diff, sign, or layer. Every preset is a `ConfigLayer`, so it composes through the same `Config::with()` call as any other layer.

Apply one or several onto your own cache with [`Config::with()`](/advanced/config-composition); presets are pure data and never receive a cache. Every rule is namespaced `preset.<area>.*`, so a later layer that redefines it by name overrides predictably.

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Preset\Presets;

// A preset on its own; apply it onto a Config you build with your cache:
$config = (new Config($cache))->with(Presets::scannerBlocking());

// Inspect / serialize the underlying portable schema:
$schema = Presets::scannerBlocking()->toArray();

// Stack several presets, then your own rules last (later layers win by name):
$config = (new Config($cache))->with(
    Presets::scannerBlocking(),
    Presets::sensitivePathBlocking(),
    $myPortable,
);
```

Preset rules emit the same [observability events](/advanced/observability) as hand-written ones; wire your PSR-14 dispatcher into the `Config` you apply onto (`new Config($cache, $dispatcher)`).

## Shipped presets

| Preset | Rules (namespaced `preset.<area>.*`) |
|--------|--------------------------------------|
| `scannerBlocking()` | `preset.scanner.known-tools` (known scanner/exploit User-Agents) and `preset.scanner.suspicious-headers` (requests missing the standard browser `Accept` / `Accept-Language` / `Accept-Encoding` headers). |
| `sensitivePathBlocking()` | `preset.sensitive-path.probes`: pattern blocklist for `/.git`, `/.svn`, `/.hg`, `/.env*`, `/.aws/credentials`, `/.htpasswd`, `/.htaccess`, `/.DS_Store`. |

Resolve any preset by name with `Presets::get($name)` (a `PortableConfig`), passing one of the `Presets::names()` constants.

## Conventions and overrides

- The shipped presets target signals that are universal across applications (scanner User-Agents, missing browser headers, well-known sensitive paths), so they assume nothing about your routing. A preset you build yourself is a `PortableConfig`, so it can key on whatever fits your environment, including routes your own apps standardize.
- Adapt a preset with the narrowest tool that fits: its own parameters first, the `configure:` closure where one exists, and only then an override by name. The table below names the knob per preset.

### Choosing the knob

**1. Preset parameters.** Most presets take the values you are likely to change - a throttle's `limit`/`period`, a data file, a paranoia level. A parameterized preset stays a preset: it keeps receiving upstream updates.

**2. The `configure:` closure (OWASP CRS).** Both CRS presets hand you the `CoreRuleSetMatcher` before the first request, which is where CRS tuning belongs - `disable($ruleId)`, `excludeTarget*()`, `applyRuleExclusions()`, `addManipulator()`. See [Tuning False Positives](/features/owasp-crs#tuning-false-positives).

**3. Override by name.** A later layer that defines a rule with the same name replaces it (see [Composition](/advanced/config-composition#merge-semantics)).

This is for rules that are **not yours to edit**: a vendor baseline, a signed `PortableConfig` loaded from a store, another tenant's layer. There you cannot change the call that created the rule, so a later same-named rule is the only hedge - and since no section offers a `removeRule()`, neutralizing an unwanted rule means overriding it with one that never matches.

In a config you assemble yourself you rarely need any of this: do not apply the preset you do not want. The one wrinkle is `scannerBlocking()`, the only shipped preset that bundles more than one rule. If you want just its scanner-UA half, wire that half directly rather than applying the bundle and overriding the other rule:

```php
// Instead of Presets::scannerBlocking() plus an override of suspicious-headers:
$config->blocklists->knownScanners('preset.scanner.known-tools');
```

That keeps the curated default pattern list and adds no second layer.

| Preset | Rule name | Tune it with |
|--------|-----------|--------------|
| `Presets::scannerBlocking()` | `preset.scanner.known-tools`, `preset.scanner.suspicious-headers` | No parameters. Override by name, or hand-wire `blocklists->knownScanners()` / `suspiciousHeaders()` with your own pattern list. |
| `Presets::sensitivePathBlocking()` | `preset.sensitive-path.probes` | No parameters. Override by name to add or drop path patterns. |
| CRS `Presets::blocklist()` | `Presets::BLOCKLIST_RULE_NAME` | `paranoiaLevel:`, `anomalyThreshold:`, `logger:`, `configure:`. An override discards the whole engine - almost never what you want. |
| CRS `Presets::fail2ban()` | `Presets::FAIL2BAN_RULE_NAME` | The same, plus `threshold:`, `period:`, `ban:`. |
| Bad-IPs `Presets::blocklist()` | `Presets::BLOCKLIST_RULE` | `dataFile:` for your own snapshot. |
| Bad-IPs `Presets::track()` | `Presets::TRACK_RULE` | `period:`, `dataFile:`. |
| Bots `Presets::blockAiCrawlers()` | `Presets::AI_BLOCK_RULE` | No parameters. Override by name to narrow or widen the crawler list. |
| Bots `Presets::throttleAiCrawlers()` | `Presets::AI_THROTTLE_RULE` | `limit:`, `period:`. Both throttles key on the client IP through the evaluating `Config`'s resolver, so behind a proxy set a [`TrustedProxyResolver`](/features/safelists-blocklists#ip-resolution) on the `Config` rather than overriding the rule. |
| Bots `Presets::throttleSeoCrawlers()` | `Presets::SEO_THROTTLE_RULE` | `limit:`, `period:`. |

::: warning An override is a replacement, not a patch
The later rule wins whole: you rebuild it and own it from then on. Upstream changes to that rule - new AI-crawler tokens, new scanner patterns, a re-imported CRS snapshot - no longer reach your deployment, silently and without an error. Prefer a parameter or `configure:` wherever one exists, and where you do override, say in a comment which knob was missing.
:::

> **Note:** `scannerBlocking()`'s `suspicious-headers` rule is the more aggressive of the two: some legitimate API clients, privacy tools, and embedded browsers also omit `Accept-*` headers. If your traffic includes non-browser clients, wire `knownScanners()` alone instead of applying the bundle - or, when the bundle comes from a layer you do not own, override `preset.scanner.suspicious-headers` by name.

## Versioning and update checks

`Presets::VERSION` identifies the bundled rule catalogue and is bumped whenever a preset's rule set changes in a way integrators should review. `Presets::version()` is a convenience accessor for the same value.

Phirewall ships **no** update-check mechanism and performs **no** network I/O. To surface "a newer ruleset is available", compare `Presets::VERSION` against a release feed you trust (Packagist, an internal config service, a versioned JSON document behind HTTPS, and so on) with `version_compare()`:

```php
use Flowd\Phirewall\Preset\Presets;

// $latestFromYourFeed comes from a source YOU control and trust.
if (version_compare(Presets::VERSION, $latestFromYourFeed, '<')) {
    // A newer preset catalogue is available; review and upgrade phirewall.
}
```

Fetching `$latestFromYourFeed` is the integrator's job; phirewall hardcodes no remote endpoint.

## Caching expensive preset data

This section only matters when a preset parses a large data source on construction - a rule-set file, an IP feed. phirewall's own presets parse no such sources and need no cache; the companion preset packages that do - OWASP CRS rule files, the bad-IP snapshot - use exactly this mechanism. Because a `Config` is built on every request under PHP-FPM, such parsing would run per request; `Flowd\Phirewall\Support\CompiledDataCache` removes that cost with a two-level cache for `var_export`-able plain data:

```php
use Flowd\Phirewall\Support\CompiledDataCache;

// The underlying primitive; in a preset matcher the instance
// arrives via CompiledDataCacheAware instead (see below).
$cache = new CompiledDataCache($cacheDirectory);
$sourceFiles = glob($rulesPath . '/*.conf') ?: [];

$ruleData = $cache->load(
    'my-preset-rules',                          // developer-defined identifier
    $sourceFiles,                               // newest mtime invalidates the cache
    fn(): array => parseRuleFiles($sourceFiles) // runs only on a cache miss
);
// $ruleData is the plain array your preset builds its matchers from.
```

The first level memoizes per process, so a warm PHP-FPM worker pays no parsing cost after its first request. The second level persists a compiled PHP artifact in the given directory and loads it via `include`, so OPcache serves it from shared memory even for cold workers. Editing a source file rebuilds on the next request; long-running workers (FrankenPHP, RoadRunner, Swoole) can additionally drop the in-process level with `CompiledDataCache::clearProcessCache()` when a deployment does not change the source mtimes.

The cache stores only plain arrays: cache the parsed data your objects are built from, not the objects themselves, and rebuild the objects from the returned array on each load. A builder returning anything but scalars, `null`, or nested arrays makes `load()` throw an `InvalidArgumentException` - unlike the silently degrading cache failures (an unwritable directory, a corrupt artifact), this surfaces a programming error instead of reviving objects through `__set_state()`.

The artifact is executed as PHP, so the directory needs the same trust as a compiled DI container: use a framework cache directory outside the web root, writable by the PHP-FPM user - for example `var/cache/phirewall` in TYPO3 or Symfony, `storage/framework/phirewall` in Laravel.

Wiring is a single integrator step:

```php
$config->setCompiledDataCache(new CompiledDataCache($cacheDirectory));
```

The cache travels as Config infrastructure (composition inherits it from the base layer, like the PSR-16 store). A preset matcher that builds its data lazily implements `Flowd\Phirewall\Matchers\CompiledDataCacheAware`; the `Firewall` hands the cache to every aware matcher, filter, and throttle scope before evaluation - mirroring how `ClientIpResolverAware` late-binds the IP resolver. Without a configured cache nothing is injected and the matcher builds its data directly, so caching stays an opt-in feature with no per-package wiring.

## Example

See [`examples/31-presets.php`](https://github.com/flowd/phirewall/blob/main/examples/31-presets.php) for standalone use, inspecting a preset as portable data, composing a preset with a user `Config` (overriding a rule by name), and comparing `Presets::VERSION` against your own release feed with `version_compare()`.

## Related pages

- [Config Composition](/advanced/config-composition) - how presets layer with your own rules.
- [Portable Config](/advanced/portable-config) - the data format every preset is built on.
- [Fail2Ban & Allow2Ban](/features/fail2ban) - the brute-force ban mechanism.

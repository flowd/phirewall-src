# Phirewall Bot Presets

Block AI crawlers and rate-limit aggressive SEO crawlers with [flowd/phirewall](https://github.com/flowd/phirewall).

Presets are `PortableConfig` data (and `ConfigLayer`s), materialized onto your cache with `Config::with()`.

## Installation

```bash
composer require flowd/phirewall-preset-bots
```

## Usage

```php
use Flowd\Phirewall\Config;
use Flowd\PhirewallPresetBots\Presets;

// Block AI crawlers, rate-limit SEO crawlers.
$config = (new Config($cache))->with(
    Presets::blockAiCrawlers(),
    Presets::throttleSeoCrawlers(limit: 60, period: 60),
);
```

Presets:

| Preset | Effect |
| --- | --- |
| `Presets::blockAiCrawlers()` | Blocks (403) requests whose `User-Agent` matches a known AI/LLM crawler. |
| `Presets::throttleAiCrawlers(limit, period)` | Rate-limits AI crawlers per client IP instead of blocking; stays indexable. |
| `Presets::throttleSeoCrawlers(limit, period)` | Rate-limits aggressive SEO/marketing crawlers per client IP. |

Each rule is named `preset.bots.*`; combine a later layer that redefines a name to override it.

## What it matches

`blockAiCrawlers()` targets crawlers that identify as AI/LLM agents - GPTBot, ChatGPT-User,
OAI-SearchBot, ClaudeBot, anthropic-ai, Claude-Web, CCBot, PerplexityBot, Bytespider,
Amazonbot, Meta-ExternalAgent, FacebookBot, cohere-ai, Diffbot, omgili, ImagesiftBot,
Timpibot, YouBot, DuckAssistBot. The SEO list covers AhrefsBot, SemrushBot, MJ12bot, DotBot,
DataForSeoBot, BLEXBot, rogerbot, PetalBot and similar. Full lists: `CrawlerCatalog`.

Search and link-preview agents (Googlebot, bingbot, Applebot, facebookexternalhit) are not in
either list. `Google-Extended` and `Applebot-Extended` are robots.txt opt-out tokens, not
User-Agents, so they are not matched - set those in `robots.txt`.

## Limits to be aware of

- **User-Agent matching is policy enforcement, not a security control.** It stops honest
  crawlers that send a truthful `User-Agent`; a hostile scraper can send any string. Pair this
  with the OWASP CRS and rate-limit presets for hostile traffic.
- **Throttles key on the client IP from `REMOTE_ADDR`.** Behind a proxy or CDN that is the proxy
  address, which buckets every client together. Configure a trusted client-IP resolver on the
  `Config`, or override the throttle by name.
- The catalogue is opinionated. To keep a crawler you value (for example Amazonbot or
  FacebookBot), override the rule by name with your own narrower list.

## Development

```bash
composer install
composer test     # rector (dry-run), php-cs-fixer (dry-run), phpunit, phpstan
```

## License

LGPL-3.0-or-later (dual-licensed, proprietary licensing available), like flowd/phirewall.

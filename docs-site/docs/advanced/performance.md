# Performance

Phirewall runs on every request, so its cost matters. This page shows what a
`decide()` call costs in isolation, what that means under load, and what is
left of it inside a real application. The short version: a typical rule set
costs single-digit **microseconds** per request, OWASP CRS costs about a
**millisecond**, and a blocked request is cheaper than a served one.

## Engine cost per request

Measured with the engine alone: 20,000 `decide()` calls per scenario after
warmup, `InMemoryCache` store, PHP 8.5 with OPcache and PCRE JIT, Apple
M-series laptop. The rule set is the Quick Start shape: one safelist, the
known-scanners blocklist, one path blocklist, one fail2ban, one allow2ban,
one throttle.

| Scenario | Outcome | Cost per request | Requests/sec (one core) |
|----------|---------|-----------------:|------------------------:|
| No rules at all (engine floor) | pass | 1.6 us | 640,000 |
| 6 rules, nothing matches (normal traffic) | pass | 8.1 us | 123,000 |
| 6 rules, safelist match (early exit) | safelisted | 1.4 us | 740,000 |
| 6 rules, blocklist match: scanner UA | blocked (403) | 1.9 us | 520,000 |
| 6 rules, blocklist match: path | blocked (403) | 3.2 us | 316,000 |
| 6 rules, fail2ban match below threshold | blocked (403) | 7.8 us | 129,000 |
| 6 rules, key already banned | blocked (403) | 5.2 us | 193,000 |
| 6 rules, throttle exceeded | throttled (429) | 8.7 us | 115,000 |

Two things stand out:

- **The expensive case is normal traffic**, because a request that matches
  nothing is checked against every rule. Matches exit early and are cheaper.
- **Attackers are the cheap case.** A blocklist match costs 2 to 3 us, and a
  banned key is decided by a single store lookup. The requests you block never
  reach your application, so under attack the firewall saves far more time
  than it costs.

Absolute numbers depend on your hardware and PHP build. Reproduce them on
your own machine with the bundled benchmarks:

```bash
XDEBUG_MODE=off php examples/20-rule-benchmarks.php   # rule scenarios
XDEBUG_MODE=off php examples/13-benchmarks.php        # store backends
```

## Store cost

The table above uses the in-process `InMemoryCache`. The counter rules
(fail2ban, allow2ban, throttle, track) are the ones that talk to the
[store](/features/storage): every request pays one ban lookup per ban-capable
rule, and requests a counter rule matches additionally pay a counter write.
The same scenarios per store, measured inside a Docker setup where Redis and
MariaDB run as separate containers:

| Scenario (6 rules) | InMemory | APCu | Redis | PDO/MySQL |
|--------------------|---------:|-----:|------:|----------:|
| Nothing matches (2 ban lookups) | 6 us | 6 us | 111 us | 110 us |
| Throttle counting a request | 8 us | 8 us | 213 us | 667 us |
| fail2ban match (403, counter write) | 5 us | 6 us | 160 us | 661 us |
| Key already banned (403) | 4 us | 4 us | 52 us | 55 us |

How to read it: APCu behaves like in-memory - shared counters on one server
at no measurable cost. The network stores pay roughly 50 us per round trip,
so reads (ban lookups, the every-request cost) sit around 0.1 ms for both.
Writes separate them: a Redis counter update is one round trip (~0.2 ms),
MySQL pays transaction and durability overhead (~0.7 ms). Even the worst
case - every request writing a counter through PDO/MySQL - stays under one
millisecond. Since bans decide on the read path, an attack wave hits the
cheap lookup, not the write.

## OWASP CRS cost

The [CRS preset](/features/owasp-crs) evaluates more than a hundred
ModSecurity rules per request at paranoia level 1, most of them regular
expressions over your request parameters, so its cost scales with the number
and size of arguments. Two numbers matter, depending on how PHP runs:

- **Under PHP-FPM** every request builds the firewall anew. The cost per
  request is loading the rules from the
  [compiled data cache](/features/owasp-crs#caching) plus evaluating them.
- **In a long-running worker** (FrankenPHP, RoadRunner, Swoole) the rules are
  built once per worker; only the evaluation is left.

| Request shape (paranoia level 1) | PHP-FPM, per request | Long-running worker |
|----------------------------------|---------------------:|--------------------:|
| GET without parameters | 1.1 ms | 0.14 ms |
| GET with 3 query parameters | 1.3 ms | 0.29 ms |
| POST with 8 form fields | 1.7 ms | 0.65 ms |
| SQL injection attempt (blocked) | 1.2 ms | 0.20 ms |

Measured on PHP 8.5 with OPcache and PCRE JIT in a Linux container on an ARM
machine, code on local disk. The PHP-FPM column is the whole firewall for one
request, from loading its classes to the decision (median of 120 requests,
each starting without any state of the previous one); the worker column is one
`decide()` call on a firewall that is already built.

The compiled data cache is what makes the PHP-FPM column possible: it holds
the parsed rules and the phrase lists of the rules that search for file names
and commands, ready to use. Without it the rule files are parsed and the
phrase files read on every request, which cost 10 ms in the same setup.

Combining CRS with a fail2ban preset also pays off here: once a probing client
is banned, the CRS engine no longer runs for it - the request is rejected by
the cheap banned-key lookup from the table above.

## What that means under load

Cost per request times requests per second gives the CPU share the firewall
needs. For the two typical setups:

| Sustained load | 6 rules (~8 us) | CRS PL1 under PHP-FPM (~1.3 ms) | CRS PL1 in a worker (~0.3 ms) |
|----------------|----------------:|------------------------------:|------------------------------:|
| 10 req/s | 0.008% of one core | 1.3% of one core | 0.3% of one core |
| 100 req/s | 0.08% of one core | 13% of one core | 3% of one core |
| 1,000 req/s | 0.8% of one core | 1.3 cores | 30% of one core |

Rule-of-thumb: counting rules are free at any realistic load; give CRS a
thought once you serve hundreds of uncached requests per second, and scope it
to the routes that need it if you do.

## IP list cost

Whether a client address is on a list is looked up in a table: one lookup for
the address and one per prefix length the list uses, so ten entries cost the
same as ten thousand. What a long list costs under PHP-FPM is getting the
table into the request, and that depends on where the list comes from:

| Added to a firewall | PHP-FPM, with compiled data cache | PHP-FPM, without | Long-running worker |
|---------------------|----------------------------------:|-----------------:|--------------------:|
| `blocklists->ip()` with 5 entries | 0.03 ms | 0.02 ms | 0.5 us |
| `blocklists->ip()` with 2,200 networks | 0.1 ms | 0.6 ms | 0.7 us |
| `blocklists->ip()` with 18,640 addresses | 0.4 ms | 1.4 ms | 0.3 us |
| [Bad-IP preset](/features/bad-ip-preset) (18,640 addresses) | 0.05 ms | 2.1 ms | 0.3 us |

Measured as the difference to a firewall without rules, on PHP 8.5 with
OPcache in a Linux container on an ARM machine, code on local disk. The
PHP-FPM columns are the whole firewall for one request, from loading its
classes to the decision (median of 400 requests, each starting without any
state of the previous one); the worker column is one `decide()` call on a
firewall that is already built.

A list passed as an array is read once per request, to check its entries and
to find its table in the [compiled data cache](/advanced/presets#caching-expensive-preset-data);
that is the 0.4 ms for 18,640 addresses. A list that lives in a file, like
the snapshot of the bad-IP preset, is recognised by the file's modification
time and size instead, and its table comes out of the cache ready to use.

## Inside a real application

Measured end to end on a TYPO3 site (Docker, Apache + mod_php 8.4, cached
page, median of 400 requests per run), once per store:

| Scenario | APCu | Redis | PDO/MySQL |
|----------|-----:|------:|----------:|
| Firewall middleware removed | 9.1 ms | | |
| Firewall active, 6 rules, nothing matches | 9.6 ms | 9.9 ms | 10.0 ms |
| Blocklist match (scanner user agent, 403) | 6.7 ms | | |
| Banned key (403) | 5.4 ms | 6.4 ms | 5.9 ms |

The no-match overhead on a cached page is well under a millisecond, and the
store differences drown in run-to-run noise - even with every ban lookup
going through MySQL. On uncached pages the overhead disappears entirely next
to rendering time. And the blocked cases respond *faster* than the page
itself: the request is stopped in the middleware before routing, rendering,
or content queries run.

## Keeping it fast

- **OPcache on** (it is on virtually every production setup): the firewall is
  plain PHP and profits like the rest of your code.
- **PCRE JIT on** (`pcre.jit=1`, the PHP default): every regex filter and the
  CRS `@rx` operators rely on it. See
  [PCRE JIT](/features/owasp-crs#pcre-jit).
- **Compiled data cache** for preset packages, so CRS and bad-IP data are not
  re-parsed per request. For CRS this is the difference between about one
  millisecond and about ten. See
  [Caching expensive preset data](/advanced/presets#caching-expensive-preset-data).
- **An optimized autoloader** (`composer dump-autoload --classmap-authoritative`,
  or `--optimize`) where file checks are slow. Composer's default autoloader
  asks the file system where each class is; the firewall with CRS loads more
  than a hundred classes. On a local disk that is negligible, on a slow mount (Docker on
  macOS or Windows with the code on the host, network file systems) it can
  cost more than everything else on this page together.
- **Pick the store deliberately**: APCu for a single server (as fast as
  in-memory), Redis when counters and bans must be shared (~0.1 ms of ban
  lookups per request, ~0.2 ms per counter write). PDO/MySQL works without
  extra infrastructure and stays under a millisecond even on counter writes,
  but it puts firewall traffic on your database.
- **Scope expensive rules.** A throttle with a `scope` filter skips its
  counter work for requests outside the scope, and CRS can be registered for
  the routes that actually take user input.

# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases up to 0.11.0 were made before this file existed.

## Unreleased

### Changed

- **The snapshot is loaded as a ready lookup table.** With a compiled-data cache, the preset costs about 0.05 ms per request under PHP-FPM instead of 0.6 ms (PHP 8.5, OPcache, local disk). The cache file now holds the lookup table itself; before, it held the address list, which was copied and hashed on every request to find a second cache file with the table. Decisions are unchanged. The table is an `IpLookupTable` of `flowd/phirewall`, which is new in 0.12. The cache file has a new name (`bad-ips-v2-...`); the files of earlier versions (`bad-ips-v1-...` and the `ip-matcher-...` file of the list) are not read any more and can be deleted with the rest of the cache directory.
- Require `flowd/phirewall` `>=0.12 <1.0` (was `>=0.11 <1.0`), for `IpLookupTable` and `CompiledDataCache::forget()`.

### Fixed

- **A replaced snapshot with an unchanged modification time is noticed.** A cache file is only used for a snapshot of the size it was made from, and one that does not fit is built again. Before, a deployment that gives every file one fixed time and keeps the cache directory went on blocking the addresses of the previous snapshot. A replacement of the same size and time is still not noticed; clear the cache directory on deployment if yours can produce one.
- **A replaced snapshot is noticed by a long-running worker that builds a new `Config`.** PHP remembers the time and size of the file it was asked about last. Where that was the snapshot, a matcher built after the snapshot had changed still saw the old time and size, and went on using the list the process had kept.
- **A data file that cannot be read is always reported as the `RuntimeException` of the preset.** The file was read with a silenced `file_get_contents()`, and an error handler is called for silenced warnings too. An application whose handler turns them into exceptions got that exception instead. A missing file no longer raises a warning at all; one that is there but unreadable still does, and whatever the handler throws for it is replaced.

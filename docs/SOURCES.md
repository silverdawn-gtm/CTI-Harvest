# Sources

Every crawl target is an entry in `crawler/config/sources.yaml`. The file is validated on
startup (a typo stops the command and names the field); `crawler sources list` shows what loaded.

## Entry fields

| Field | Applies to | Meaning |
|---|---|---|
| `name` | all | unique lowercase id; stored as `documents.source` |
| `adapter` | all | `rss`, `sitemap`, `wordpress`, `kev` or `nvd` |
| `entry_url` | all | where discovery starts: feed, sitemap index, WordPress posts API, or catalog |
| `rate_limit` | all | `{requests, per_seconds}`, enforced per host. Default 1 per 2.0 s |
| `license` | all | stored on every document. Default `copyrighted` (`public-domain` for kev/nvd) |
| `enabled` | all | `false` keeps the entry on file without crawling. Default `true` |
| `child_pattern` | sitemap, **required** | substring identifying child sitemaps that hold articles |
| `article_pattern` | sitemap, optional | substring every article URL must contain |

## Adapters

| Adapter | How it discovers | Best for |
|---|---|---|
| `rss` | reads the feed; a feed carries a few weeks at most | sites with no better route |
| `sitemap` | walks the sitemap index → child sitemaps → articles; whole archive, one request per article | full history |
| `wordpress` | `wp-json/wp/v2/posts`, 100 full-text posts per request | the politest option where available |
| `kev` | CISA Known Exploited Vulnerabilities JSON catalog | vulnerability facts |
| `nvd` | NVD CVE API 2.0; backfill by publication date, incremental by modification date | vulnerability facts |

## Current sources

| Source | Adapter | Notes |
|---|---|---|
| `bleepingcomputer` | rss | sitemaps mix forum threads; 3 s spacing |
| `securityweek` | rss | sitemap and WP API both return 403 |
| `projectzero` | rss | Blogger feed |
| `krebsonsecurity` | sitemap | `posts-post` child sitemaps |
| `thehackernews` | sitemap | |
| `therecord` | sitemap | |
| `talos` | sitemap | |
| `sentinelone` | sitemap | |
| `unit42` | wordpress | |
| `microsoft` | wordpress | Microsoft Security blog |
| `malwarebytes` | wordpress | API at the domain root, not `/blog` |
| `kev` | kev | public domain |
| `nvd` | nvd | public domain; 6.5 s spacing keeps under the 5 requests / 30 s unauthenticated limit |

**Deliberately not crawled:** `darkreading` (returns 403 on every article; the publisher refuses
automated clients and spoofing a browser User-Agent is not acceptable) and Google TAG (feed URL
now 404s).

## Politeness

- `robots.txt` is checked before every fetch (`core/fetch.py`).
- Per-host rate limiting, with conditional requests (ETag / Last-Modified).
- The User-Agent identifies the crawler (`Settings.user_agent`). Before wider use, set it to
  something with a real contact URL.
- Each document carries its `license`; respect publishers' terms when redistributing a corpus.
  Raw copyrighted article text is for research use only.

## Adding a source

**On an existing adapter** — add a YAML entry, no code:

```yaml
  - name: examplesec
    adapter: wordpress
    entry_url: https://example.com/wp-json/wp/v2/posts
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted
```

Run `uv run crawler sources list`, then `uv run crawler crawl --source examplesec`.

**A new adapter** — implement the `Source` protocol (`src/crawler/sources/base.py`):
`discover(since, fetcher, mode)` yields `DiscoveredItem`s and `parse(raw)` is a pure function
returning a `ParseResult`. Add its config model in `sources/catalog.py`, wire it into `sources/loader.py:build_source`,
and add tests under `tests/sources/`.

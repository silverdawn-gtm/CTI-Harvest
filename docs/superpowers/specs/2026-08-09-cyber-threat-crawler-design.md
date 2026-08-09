# Cyber Threat Intelligence Crawler — Design

**Date:** 2026-08-09
**Status:** Approved

## Purpose

Collect a corpus of recent cybersecurity attack types and patterns from public sources, normalize it into a queryable schema, and export it for training a cybersecurity prediction model.

The specific prediction target is undecided. The design therefore extracts a rich superset of fields rather than optimizing for one task, and keeps raw source documents so extraction can be redone without re-crawling.

## Requirements

| Decision | Choice |
|---|---|
| Source families | Structured feeds, security news/blogs, vendor threat reports, advisories/CERTs |
| ML target | Undecided — extract a general superset |
| Extraction | Hybrid: rules always, LLM on demand |
| Storage | PostgreSQL 16 |
| Migrations | SQLAlchemy + Alembic |
| Packaging | uv |
| Runtime | Python on Windows (`C:\Project\Crawler`); Postgres in Docker under WSL2 |
| Scope | ~1–2 year backfill, then incremental runs |
| Architecture | Custom async pipeline with pluggable source adapters |

## Environment

Docker runs inside WSL2 without Docker Desktop, so `docker compose` commands must be issued from a WSL shell. The crawler itself runs on Windows and reaches Postgres at `localhost:5432` via WSL2 localhost forwarding. `DATABASE_URL` is read from `.env`, so nothing hardcodes that boundary.

`crawler db ping` exists specifically to verify this connection before a long run, since WSL port forwarding is the most likely thing to misbehave.

## Architecture

The controlling constraint: **`core/` never imports a source, and sources never touch the database.** Adapters return plain dataclasses; the pipeline persists them. This keeps parsers testable in isolation and lets a new source be added without reading pipeline code.

```
C:\Project\Crawler
├── pyproject.toml            # uv-managed
├── docker-compose.yml        # Postgres 16 (run from WSL)
├── .env.example              # DATABASE_URL, NVD_API_KEY, LLM key
├── alembic/                  # migrations
├── src/crawler/
│   ├── cli.py                # Typer entrypoint
│   ├── config.py             # pydantic-settings, loads .env
│   ├── core/
│   │   ├── fetch.py          # async httpx client: robots.txt, per-domain limiter,
│   │   │                     #   ETag/Last-Modified cache, retry w/ jittered backoff
│   │   ├── pipeline.py       # discover → dedup → fetch → parse → extract → persist
│   │   └── models.py         # DiscoveredItem, RawDocument, ParsedDoc (dataclasses)
│   ├── sources/
│   │   ├── base.py           # Source protocol + registry
│   │   ├── nvd.py  kev.py  attack.py  abusech.py
│   │   ├── news_rss.py       # config-driven: one adapter, many news sites
│   │   ├── cisa.py
│   │   └── vendor_pdf.py
│   ├── extract/
│   │   ├── rules.py          # regex + taxonomy matching (always runs)
│   │   ├── taxonomy.py       # loads YAML dictionaries
│   │   └── llm.py            # opt-in enrichment pass
│   └── db/
│       ├── schema.py         # SQLAlchemy models
│       └── repo.py           # upsert/query functions
├── data/
│   ├── taxonomies/           # attack_types.yaml, sectors.yaml (+ generated actor/technique data)
│   └── raw/                  # gzipped archive of fetched documents
└── tests/
```

### Adapter contract

```python
class Source(Protocol):
    name: str                    # "bleepingcomputer"
    kind: Literal["feed", "api", "html", "pdf"]
    license: str                 # "public-domain" | "copyrighted" | ...
    rate_limit: RateLimit

    async def discover(self, since: datetime) -> AsyncIterator[DiscoveredItem]
    def parse(self, raw: RawDocument) -> ParsedDoc
```

`discover` is async because it pages through APIs and feeds. `parse` is sync and pure — bytes in, dataclass out — so every parser is testable against a saved fixture with no network and no database.

### Two structural decisions

**`news_rss.py` is one adapter driven by a YAML site list**, not one module per publication. BleepingComputer, The Hacker News, and Krebs differ only in feed URL and body selector, so adding a site is a config entry. A site needing genuinely custom logic can still get its own module.

**Raw bytes are archived before parsing.** Improving extraction later means re-running `parse` over stored raw documents instead of re-crawling. Parsers will be wrong at first; re-crawling a year of history to fix a regex is not an acceptable cost.

### Libraries

`httpx` + `asyncio` (fetching), `trafilatura` (article body extraction), `feedparser` (RSS), `pypdf` (vendor reports), `selectolax` (targeted HTML selectors), SQLAlchemy + Alembic (data layer), Typer (CLI), pydantic-settings (config).

Scrapy was considered and rejected: half the sources are JSON/CSV/STIX APIs rather than HTML, which fit Scrapy's spider model awkwardly, and writing to Postgres from a Twisted item pipeline forces a choice between blocking the reactor and bolting async onto it.

## Crawl politeness

Applies to every source:

- Respect `robots.txt`.
- Per-domain rate limiting with exponential backoff.
- Descriptive User-Agent including contact information.
- Prefer RSS, sitemaps, and APIs over HTML scraping.
- Conditional requests via `ETag` / `If-Modified-Since`, so incremental runs re-fetch almost nothing.
- Fetch only PDFs the publisher links publicly.

## Licensing

NVD, CISA KEV, and MITRE ATT&CK are open. News articles and vendor reports are copyrighted — acceptable for private model training under most readings, but redistribution is a separate question. Every source carries a `license` value that propagates to `documents` and is included in exports, so a redistributable subset can be filtered out. Full text is stored; if redistribution becomes a goal, the excerpt-only alternative should be revisited then.

## Database schema

Expected volume for a 2-year backfill: roughly 30–60k news/advisory documents and ~50k CVEs. Small for Postgres — plain tables with good indexes, no partitioning.

### Core tables

| Table | Purpose | Key columns |
|---|---|---|
| `sources` | Registry + per-source state | `name` PK, `kind`, `license`, `enabled`, `last_success_at` |
| `documents` | One row per fetched URL | `id`, `source`, `url`, `url_hash` **UNIQUE**, `title`, `published_at`, `fetched_at`, `content_hash`, `body_text`, `raw_path`, `etag`, `last_modified`, `http_status`, `license` |
| `records` | Extracted view of a document | `document_id` FK, `primary_attack_type`, `summary`, `confidence`, `extraction_version`, `extracted_by` (`rules`\|`llm`), `extra` JSONB |
| `vulnerabilities` | CVE-centric facts | `cve_id` PK, `published`, `cvss_v3`, `cvss_vector`, `epss`, `kev_listed`, `kev_added_date`, `vendor`, `product`, `description` |
| `crawl_runs` | Per-run observability | `id`, `source`, `started_at`, `finished_at`, `discovered`, `fetched`, `parsed`, `failed`, `status` |
| `fetch_errors` | Retryable failures | `url`, `source`, `error_class`, `attempts`, `last_attempt_at` |

### Entity tables and junctions

`actors`, `techniques` (ATT&CK), `sectors`, and `attack_types`, each with a `document_<x>` junction carrying `confidence` and `matched_text`. Plus `document_cves` and `iocs` (`type` enum: ip/domain/url/hash/email, `value`, `document_id`).

Attack types are **multi-label**: real incidents chain (phishing → credential theft → ransomware), and forcing a single label discards training signal. `records.primary_attack_type` holds the highest-confidence label for convenience; the junction holds all of them. Multi-label can always be collapsed to single-label at export.

### Why normalized junctions rather than JSONB arrays

The two likely ML targets pull in opposite directions: trend forecasting needs `GROUP BY technique, month` aggregations, while text classification wants a flat row. Junctions serve both, and export flattens them into arrays. JSONB-first would make aggregation queries painful and hard to index. The `records.extra` JSONB column absorbs unmodeled fields, so an unexpected field never forces a migration mid-crawl.

### Three columns doing real work

- **`url_hash` UNIQUE** is the dedup mechanism. Discovery may re-emit the same URL indefinitely; inserts are idempotent upserts.
- **`content_hash`** catches both an unchanged page on re-fetch (skip re-parsing) and syndicated articles republished across sites. Near-duplicates must be collapsed before training.
- **`extraction_version`** allows re-running extraction over archived raw documents while keeping both versions side by side for comparison, rather than destructively overwriting labels.

### Postgres-specific choices

A generated `tsvector` column over `title || body_text` with a GIN index for corpus exploration. `JSONB` for `extra`. All timestamps `timestamptz` stored UTC — sources report local time, and mixing them would silently corrupt time-series work.

### Raw archive

Stored on disk, not in the database: `data/raw/<source>/<yyyy>/<mm>/<url_hash>.html.gz`, with `documents.raw_path` pointing at it. Keeping gzipped HTML and PDFs out of Postgres keeps `pg_dump` fast and the database portable.

## Extraction

### Stage 1 — Normalize

Refang defanged indicators (`hxxps://evil[.]com`, `192.168.1[.]1`) before any matching; regexes fail on them otherwise. Original text is preserved for provenance.

### Stage 2 — Rules (always run, free, deterministic)

- **CVEs**: `CVE-\d{4}-\d{4,7}`. Near-perfect precision.
- **IOCs**: IPv4/v6, domains, URLs, MD5/SHA1/SHA256, emails. False-positive controls: drop RFC1918 and reserved ranges, drop `example.com`/`localhost`, reject version strings resembling IPs, require domains to end in a valid public suffix.
- **Actors**: alias-table lookup. `APT29` / `Cozy Bear` / `Midnight Blizzard` / `UNC2452` must collapse to one entity or actor counts are meaningless.
- **ATT&CK techniques**: match both IDs (`T1566`) and technique names.
- **Attack types and sectors**: weighted keyword scoring from YAML; confidence derived from score margin.

The ATT&CK adapter ingests the MITRE STIX bundle, which contains canonical group aliases and technique names. Actor and technique dictionaries are therefore generated from crawled data rather than hand-maintained. Only `attack_types.yaml` and `sectors.yaml` are hand-written, and both are small.

### Stage 3 — LLM enrichment (opt-in, bounded)

`crawler enrich --limit 500 --filter "primary_attack_type IS NULL"` sends selected documents to an LLM with a strict JSON schema matching the record fields.

Two invariants: it **never overwrites** rule output — it inserts a new `records` row with `extracted_by='llm'` and its own `extraction_version`, so the two can be diffed. And it is always explicitly invoked with a limit, so cost is bounded by the operator, never by crawl volume.

### Provenance

Junction rows store `matched_text` and character offsets. When a label looks wrong, the responsible sentence is identifiable without re-reading whole articles.

### Known limitation

Keyword-based attack-type classification will land around 70–80% accuracy, weakest on articles that describe an attack without naming its type. Extraction is versioned and raw documents archived precisely because the first pass is a starting point, not a finished labeler. The LLM pass addresses the hard residue and also measures rule quality on a sample.

## Operations

### CLI

```
db ping | db upgrade                    # ping verifies the WSL Postgres is reachable
sources list                            # registered sources, license, last success
backfill --since 2024-08-01 [--source X] [--dry-run]
crawl                                   # incremental: each source resumes from last_success_at
enrich --limit N --filter "..."         # LLM pass, bounded
reparse --since ... [--source X]        # re-run parse+extract over archived raw, no network
export --format jsonl|parquet --out ...
stats | doctor --source X               # doctor hits live endpoints to detect site drift
```

`reparse` is the payoff for archiving raw bytes: fixing a regex costs minutes of local reprocessing instead of a re-crawl.

### Error handling

Failure isolation at three levels: a bad document is logged to `fetch_errors` and skipped; a failing source is quarantined for that run; only a database outage aborts everything.

Retries use exponential backoff with jitter (max 4 attempts) on 429/5xx/timeouts, honour `Retry-After`, and never retry 404/410. After 5 consecutive failures against one domain, a circuit breaker pauses that source for the remainder of the run and records the reason in `crawl_runs`.

### Resumability

A 2-year backfill runs for hours and will be interrupted. Commits happen per batch, not per run, and `url_hash` dedup makes re-running `backfill` skip completed work. Ctrl-C followed by restart is a supported, tested path.

NVD receives special handling as the strictest limiter (5 requests/30s without an API key, 50 with) and the largest backfill. Its adapter carries its own rate limit and pages by date window, so a failure resumes at the window boundary rather than restarting.

### Parser drift

The main long-term risk is a site changing markup while the crawler keeps storing rows with empty bodies. Guards: `parse` warns when `body_text` is under 200 characters or the title is missing; `crawl_runs` tracks per-source parse-failure rate; `stats` flags any source whose rate exceeds 20%. Loud failure beats a quietly poisoned corpus.

## Testing

pytest + pytest-asyncio. No network access anywhere in the suite.

- **Parser tests carry the most weight**: saved fixture files per source asserting extracted fields. Adding a source means adding a fixture.
- **Extraction tests are table-driven** and deliberately include false-positive cases: defanged indicators, private IPs, version strings resembling IPs, `example.com`.
- **HTTP behaviour** via a mock transport: assert rate limiting delays, 429 triggers backoff, `ETag` produces conditional requests.
- **Database tests run against real Postgres** — a `crawler_test` database in the same WSL container, each test wrapped in a rolled-back transaction. testcontainers is deliberately avoided: it drives the Docker socket, and Docker lives in WSL while pytest runs on Windows.
- **One end-to-end test**: fixtures → full pipeline → database assertions.

Live sites are never contacted by tests. `crawler doctor --source X` exists for on-demand verification against real endpoints.

## Export

JSONL and Parquet, with junction tables flattened into arrays, deterministic ordering, and the per-source `license` field included so copyrighted sources can be filtered out of a redistributable set.

## Out of scope

- Choosing or training the prediction model.
- A continuously running daemon or scheduler. `crawl` is invoked manually or by an external scheduler.
- Authenticated, paywalled, or dark-web sources.
- A web UI or dashboard. `stats` and SQL are the interfaces.

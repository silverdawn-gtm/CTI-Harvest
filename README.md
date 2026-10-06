# Kunjadi — Cyber Threat Intelligence Pipeline

Kunjadi crawls cybersecurity news, advisories and vulnerability feeds into PostgreSQL, then
extracts **CTI entities and relations** (threat groups, malware, CVEs, infrastructure, …) from
every article into structured JSON. Output is held to a fixed 15-type ontology: the extractor
cannot emit a type or relation that is not in `crawler/config/ontology.json`.

```
 publishers / feeds ──► crawl ──► PostgreSQL + raw archive ──► extract ──► data/extracted/<url_hash>.json
 (RSS, sitemap, WP API,   │        documents, vulnerabilities     │         entities (char offsets)
  CISA KEV, NVD)          │                                       │         + relation triples
                    rate-limited,                       rules (regex + ATT&CK)
                    robots-aware                        + schema-constrained LLM
```

## Repository layout

```
crawler/                    the pipeline (Python 3.12, uv)
  config/sources.yaml       every crawl source: adapter, URL, rate limit, license
  config/ontology.json      the 15 entity types and the relation triples allowed between them
  src/crawler/sources/      crawl adapters: rss, sitemap, wordpress, kev, nvd
  src/crawler/core/         fetcher, per-host rate limiter, raw archive, crawl loop
  src/crawler/db/           SQLAlchemy models, repository functions, sessions
  src/crawler/extraction/   tokenizer, rules, LLM client, validator, runner
  src/crawler/cli.py        `crawler` command line
  alembic/                  database migrations
  tests/                    pytest suite (no network)
  scripts/                  data-quality helpers
docs/                       project documentation (start with docs/README.md)
legacy/text-extractor/      the original standalone extractor web app, kept for reference
```

## Quick start

Everything runs from `crawler/`. You need Python 3.12+, [uv](https://docs.astral.sh/uv/) and
Docker (for PostgreSQL).

```powershell
cd crawler
docker compose up -d                       # PostgreSQL 16 on host port 5433
Copy-Item .env.example .env                # then add an LLM provider key (optional for rules-only)
uv sync
uv run crawler db upgrade                  # create the schema
uv run crawler crawl --source kev          # fetch CISA's Known Exploited Vulnerabilities
uv run crawler extract --rules-only --limit 20     # no API key needed
uv run crawler extract --limit 50                  # rules + schema-constrained LLM pass
```

On Linux/macOS use `cp .env.example .env`. Extraction output lands in
`crawler/data/extracted/<url_hash>.json`, one file per document.

## Documentation

| Doc | What it covers |
|---|---|
| [docs/README.md](docs/README.md) | Index of all documentation |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the crawl and extraction pipelines work |
| [docs/USAGE.md](docs/USAGE.md) | Every CLI command and option, configuration, output format |
| [docs/ONTOLOGY.md](docs/ONTOLOGY.md) | The 15 entity types and 26 relations |
| [docs/SOURCES.md](docs/SOURCES.md) | Crawl sources, adapters, adding a source |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Database tables |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Setup, tests, lint, conventions, repo history |

## Tests

```powershell
cd crawler
uv run pytest
```

Create `.env` first (`DATABASE_URL` is required by the settings). Database tests also need
`TEST_DATABASE_URL` and a running Postgres; without it they are skipped.
No test touches the network or a real LLM.

## History

`crawler/` and `legacy/text-extractor/` were imported with their full commit histories
(`git log -- crawler`, `git log -- legacy/text-extractor`).

# Kunjadi — Cyber Threat Intelligence Pipeline

Crawls cybersecurity news, advisories and vulnerability feeds into PostgreSQL, then extracts
CTI entities and relations (threat groups, malware, CVEs, infrastructure, …) from every
article into structured JSON, held to a fixed 15-type ontology.

## Layout

```
crawler/                 the pipeline (Python 3.12, uv)
  config/sources.yaml    every crawl source: adapter, URL, rate limit, license
  config/ontology.json   the 15 entity types and the relation triples allowed between them
  src/crawler/sources/   crawl adapters (RSS, sitemap, WordPress API, CISA KEV, NVD)
  src/crawler/core/      fetcher, per-host rate limiter, raw archive, crawl pipeline
  src/crawler/db/        SQLAlchemy models and session
  src/crawler/extraction/ rules + LLM entity/relation extractor
  src/crawler/cli.py     `crawler crawl | backfill | clean | export | extract | stats ...`
  tests/                 pytest suite
  alembic/               database migrations
legacy/text-extractor/   the original standalone extractor web app, kept for reference;
                         its extraction logic now lives in crawler/src/crawler/extraction/
docs/CTI_INTEGRATION.md  the integration spec that merged the two projects
```

## Quick start

Everything runs from `crawler/`. Postgres runs in Docker (see `crawler/README.md` for the WSL
details).

```powershell
cd crawler
docker compose up -d
Copy-Item .env.example .env        # then fill in DATABASE_URL and an LLM provider key
uv sync
uv run crawler db upgrade
uv run crawler crawl --source kev
uv run crawler extract --rules-only --limit 20      # no API key needed
uv run crawler extract --limit 50                   # rules + schema-constrained LLM pass
```

Extraction output: `crawler/data/extracted/<url_hash>.json`, one file per document, with
entity character offsets and relation triples. See `crawler/README.md` for every command
and option.

## Tests

```powershell
cd crawler
uv run pytest
```

Database tests need `TEST_DATABASE_URL` and a running Postgres.

## History

`crawler/` and `legacy/text-extractor/` were imported with their full commit histories
(`git log -- crawler` / `git log -- legacy/text-extractor`).

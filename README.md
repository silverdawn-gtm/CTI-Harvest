# Cyber Threat Intelligence Crawler

Collects recent cybersecurity attack data into PostgreSQL for model training.
See `docs/superpowers/specs/2026-08-09-cyber-threat-crawler-design.md` for the design.

## Setup

Postgres runs in Docker under WSL. **From a WSL shell:**

```bash
docker compose up -d
docker exec crawler-db createdb -U crawler crawler_test
```

**From PowerShell:**

```powershell
Copy-Item .env.example .env
uv sync
uv run crawler db upgrade
uv run crawler db ping
```

## Configuration

- `config/sources.yaml` — every crawl source: adapter (`rss`, `sitemap`, `wordpress`, `kev`,
  `nvd`), entry URL, rate limit and license. Adding a publication on an existing adapter is a
  new entry here, no code. The file is validated on startup; a typo stops the command with the
  offending field named.
- `config/ontology.json` — the 15 CTI entity types and the relation triples allowed between
  them. The extractor cannot produce anything outside it.

## Usage

```powershell
uv run crawler sources list
uv run crawler crawl --source kev
uv run crawler stats
```

## Extraction

Turns crawled documents into entities (with character offsets into `body_text`) and relation
triples, written to `data/extracted/<url_hash>.json`. A file existing means the document is
done, so re-running continues where the last run stopped.

```powershell
uv run crawler extract --rules-only --limit 20      # regex + ATT&CK dictionary only, no API key
uv run crawler extract --source unit42 --limit 50    # rules, then the LLM pass
uv run crawler extract --force --limit 10            # redo documents that already have output
```

The LLM pass needs `LLM_PROVIDER` and that provider's API key in `.env` (see `.env.example`).
Mistral, Gemini and Grok are called through their OpenAI-compatible endpoints with a strict
JSON schema generated from `config/ontology.json`. Requests go through the same per-host rate
limiter as the crawler (`LLM_REQUESTS_PER_MINUTE`, `LLM_PARALLEL`). A document whose LLM pass
failed is not written and is retried next run; three documents in a row with every sentence
failing stop the run.

## Tests

```powershell
uv run pytest
```

Tests never touch the network. Database tests need `TEST_DATABASE_URL` and are
skipped without it.

# Usage

All commands run from `crawler/` via `uv run crawler …`.

## Setup

```powershell
docker compose up -d                                       # Postgres 16, host port 5433
docker exec crawler-db createdb -U crawler crawler_test    # once, for the test suite
Copy-Item .env.example .env
uv sync
uv run crawler db upgrade
uv run crawler db ping
```

> The compose file publishes Postgres on **5433** (a native Windows Postgres may hold 5432) and
> `.env.example` uses `127.0.0.1` rather than `localhost`, because Windows resolves `localhost`
> to IPv6 first and the container listens on IPv4 only. Adjust both for your machine.

## Commands

| Command | Purpose |
|---|---|
| `crawler db ping` | verify the database is reachable |
| `crawler db upgrade` | apply Alembic migrations |
| `crawler sources list` | list registered sources (name, adapter kind, license) |
| `crawler crawl [--source a,b] [--since-days 30]` | incremental fetch of new documents |
| `crawler backfill --since 2024-08-01 [--source a,b]` | load history, by publication date |
| `crawler clean [--apply]` | remove non-article pages/duplicates, recover dates (dry run unless `--apply`) |
| `crawler export [--format jsonl or parquet] [--out data/export]` | write `documents.*` and `vulnerabilities.*` |
| `crawler extract …` | entity/relation extraction (below) |
| `crawler stats` | document count per source |

### `crawler extract`

| Option | Meaning |
|---|---|
| `--source a,b` | restrict to sources |
| `--limit N` | at most N documents (default 50) |
| `--rules-only` | regex + dictionary pass only; no API key; writes to `data/extracted-rules/` |
| `--out DIR` | output directory (default `data/extracted`) |
| `--force` | redo documents that already have output |
| `--retry-failed` | also retry documents that failed 3 runs |

```powershell
uv run crawler extract --rules-only --limit 20
uv run crawler extract --source unit42 --limit 50
uv run crawler extract --force --limit 10
```

## Configuration

Settings come from `.env` (see `.env.example`) or environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | – (required) | SQLAlchemy URL, e.g. `postgresql+psycopg://crawler:crawler@127.0.0.1:5433/crawler` |
| `TEST_DATABASE_URL` | – | separate DB for tests |
| `RAW_ARCHIVE_DIR` | `data/raw` | gzipped raw payload archive |
| `LLM_PROVIDER` | `mistral` | `mistral`, `gemini` or `grok` |
| `LLM_PARALLEL` | `4` | LLM requests in flight |
| `LLM_REQUESTS_PER_MINUTE` | `30` | per-provider-host ceiling |
| `<PROVIDER>_API_KEY` | – | `MISTRAL_API_KEY`, `GEMINI_API_KEY`, `GROK_API_KEY` |
| `<PROVIDER>_MODEL` | see `.env.example` | first model to try |
| `<PROVIDER>_FALLBACK_MODELS` | see `.env.example` | comma-separated fallbacks |

Never commit `.env`; it is git-ignored. Model names change often — if a provider rejects the
model (HTTP 404), pick a current one from its console.

File-based configuration: `config/sources.yaml` ([SOURCES.md](SOURCES.md)) and
`config/ontology.json` ([ONTOLOGY.md](ONTOLOGY.md)).

## Extraction output

One file per document: `data/extracted/<url_hash>.json`.

```json
{
  "document_id": 123,
  "url": "https://…",
  "url_hash": "…",
  "source": "unit42",
  "title": "…",
  "published_at": "2026-08-01T00:00:00+00:00",
  "extracted_at": "2026-10-05T10:00:00+00:00",
  "ontology_version": "2026-10-04",
  "llm_model": "ministral-14b-latest",
  "sentences": 42,
  "entities": [
    {"id": 0, "text": "APT28", "type": "ThreatGroup", "start": 120, "end": 125,
     "sentence": 3, "origin": "rules"}
  ],
  "relations": [
    {"source": 0, "relation": "uses", "target": 1, "sentence": 3}
  ],
  "warnings": [],
  "dropped": []
}
```

- `start`/`end` are character offsets: `body_text[start:end] == text`.
- `origin` is `rules` or `llm`.
- `relations[].source/target` are entity `id`s; a relation reads *source → relation → target*.
- `warnings` lists sentences that fell back to rules-only; `dropped` lists entities/relations
  the validator rejected, with reasons.
- `llm_model` is `null` for rules-only output.

## Raw archive and exports

- `data/raw/<source>/<yyyy>/<mm>/<url_hash>.<ext>.gz` — original payloads.
- `data/export/` — `crawler export` output. `data/` is git-ignored and can be large.

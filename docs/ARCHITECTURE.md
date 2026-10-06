# Architecture

Two pipelines share one PostgreSQL database and one set of politeness controls.

## 1. Crawl pipeline

`crawler crawl` / `crawler backfill` → `core/pipeline.py:run_source` for each enabled source.

```
sources.yaml ─► loader ─► Source adapter ─discover()─► items ─► Fetcher ─► RawArchive (gzip)
                                                                  │            │
                                                          rate limiter     parse()
                                                          robots.txt          │
                                                                  documents / vulnerabilities (upsert)
```

1. **Catalog** (`sources/catalog.py`, `sources/loader.py`). `config/sources.yaml` is validated
   on startup; a typo stops the command and names the field. Each entry becomes a registered
   source built by its adapter.
2. **Adapters** (`sources/`). Each implements `discover(since, fetcher, mode)` (yield items to
   fetch) and `parse(raw)` (return documents and/or vulnerability facts):
   `news_rss`, `sitemap`, `wordpress` (REST API), `kev` (CISA catalog), `nvd` (CVE API 2.0).
3. **Fetcher** (`core/fetch.py`). One shared HTTP client; checks `robots.txt`, applies the
   per-host rate limit (`core/ratelimit.py`), sends conditional requests (ETag /
   Last-Modified) and treats 304 as "nothing new".
4. **Archive** (`core/archive.py`). Every fetched payload is stored gzipped under
   `data/raw/<source>/<yyyy>/<mm>/<url_hash>.<ext>.gz` before parsing, so documents can be
   re-parsed without re-crawling.
5. **Persistence** (`db/repo.py`). Documents are upserted by `url_hash`; a payload whose content
   hash is already stored is skipped. Progress is committed every 50 items or 1000 rows.
6. **Failure handling.** Five consecutive fetch failures open a circuit breaker for that source
   (`status=circuit_open`); a dead discovery URL marks the run `discover_failed`. Neither stops
   other sources. Up to 6 sources run concurrently; the rate limit is per host, so this is no
   less polite to any one publisher.
7. **Cleaning** (`crawler clean`). Dry-run by default; removes tag/author/category pages, bodies
   under 500 characters (KEV excepted), duplicate bodies, and recovers missing dates from URLs.

## 2. Extraction pipeline

`crawler extract` → `extraction/runner.py` → `extraction/pipeline.py:extract_text`.

```
documents (body_text) ─► sentence split + tokenize ─► rules ─┐
                                                              ├─► merge ─► validate ─► char offsets ─► JSON
                                           LLM (strict JSON schema) ┘   (rules win overlaps)
```

1. **Selection.** `runner` picks documents with no output file yet (new ones first, then
   previously failed ones), up to `--limit`. A file in the output directory means "done", so
   re-runs resume.
2. **Tokenizer** (`tokenizer.py`). Splits sentences without breaking on abbreviations; separates
   punctuation but keeps hashes, IPs, URLs, defanged domains (`evil[.]com`) and `T1566.001` whole.
3. **Rules** (`patterns.py`, `rules.py`). Regexes for URLs, IPs, domains, hashes, file names,
   CVE/MS IDs, ATT&CK IDs and dates; dictionary matching (ATT&CK groups, malware, tools,
   techniques, countries) with longest-match-wins. Each token belongs to at most one entity.
4. **LLM pass** (`llm.py`, `client.py`). One request per sentence, run concurrently
   (`LLM_PARALLEL`) behind the shared rate limiter. The prompt (`resources/extract.txt`) lists
   the types, the allowed relations and what the rules already found. The reply is forced at
   the API level to a JSON schema generated from `ontology.json` (`response_format: json_schema`,
   `strict: true`), so it can only name ontology types and relations. Mistral, Gemini and Grok
   are all reached through one OpenAI-compatible client with retry/backoff and model fallback.
5. **Merge + validate** (`pipeline.py`, `validator.py`). Rule spans win any overlap; LLM
   entities may only use free tokens. Relations not permitted between the two entity types (per
   the ontology) are dropped and recorded in `dropped`; inverse names are normalised.
6. **Offsets** (`formatter.py`). Entities map back to character offsets in the original text
   (`text[start:end] == mention`).
7. **Write** (`runner.py`). Atomic write of `<out>/<url_hash>.json`.

### Failure semantics

- One failed LLM sentence falls back to rules-only for that sentence (a warning is recorded).
- A document with every sentence failing is not written; `<url_hash>.failed.json` counts failed
  runs. Failed documents are retried after new ones until they have failed 3 runs
  (`--retry-failed` / `--force` override).
- HTTP 400/401/403/404 from the provider (bad key, request or model), or three documents in a
  row with every sentence failing, abort the run (`LLMFatal` / `ExtractionAborted`).
- `--rules-only` writes to `data/extracted-rules/` so it never marks a document done for the
  LLM pass.

## Module map

| Path | Responsibility |
|---|---|
| `cli.py` | Typer app: `crawl`, `backfill`, `clean`, `export`, `extract`, `stats`, `sources list`, `db ping/upgrade` |
| `config.py` | `Settings` (pydantic-settings, reads `.env`) |
| `core/` | `fetch`, `ratelimit`, `archive`, `pipeline`, `models` (item/raw/parsed dataclasses) |
| `sources/` | adapters + catalog/loader |
| `db/` | `schema` (tables), `repo` (queries), `session` |
| `export.py` | corpus export to JSONL / Parquet |
| `extraction/` | see above; `ontology.py` loads and validates `ontology.json` |

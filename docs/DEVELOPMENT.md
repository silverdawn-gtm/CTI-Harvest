# Development

## Environment

- Python 3.12+ (`crawler/.python-version`), [uv](https://docs.astral.sh/uv/) for dependencies
- Docker for PostgreSQL 16 (`crawler/docker-compose.yml`)

```powershell
cd crawler
docker compose up -d
docker exec crawler-db createdb -U crawler crawler_test
Copy-Item .env.example .env
uv sync
uv run crawler db upgrade
```

## Tests

```powershell
uv run pytest                    # whole suite
uv run pytest tests/extraction   # one area
```

- No test touches the network or a real LLM; HTTP and LLM calls are faked.
- Database tests use `TEST_DATABASE_URL` (a separate database, dropped and recreated each
  session) and run inside a transaction that is rolled back. Without it they are
  skipped, not failed. `DATABASE_URL` must still be set (copy `.env.example` to `.env`), because
  `Settings` requires it; without it the database tests error at setup instead of skipping.
- `asyncio_mode = "auto"`: async tests need no decorator.

Layout mirrors the source: `tests/core`, `tests/db`, `tests/sources`, `tests/extraction`, plus
top-level CLI, config and end-to-end tests.

## Lint

```powershell
uv run ruff check .
uv run ruff format --check .
```

Line length 100; rules `E, F, I, UP, B`. `UP017` is ignored on purpose: stored timestamps use
`datetime.now(timezone.utc)`. Long regex/TLD tables in `extraction/patterns.py` are exempt from
`E501`.

## Database migrations

```powershell
uv run alembic revision --autogenerate -m "describe change"
uv run crawler db upgrade
```

Edit models in `src/crawler/db/schema.py`, generate the migration, review it, commit both.

## Conventions

- **Config over code.** Sources and the ontology live in `config/`; adding either should not
  need a code change unless it is a brand-new adapter.
- **`parse()` is pure.** Bytes in, typed facts out; no network or database access, so adapters
  are testable from fixtures.
- **Never exceed the ontology.** Anything that produces entities or relations must go through
  `validator.validate`.
- **Per-host politeness is non-negotiable.** All outbound HTTP goes through `Fetcher` (crawl) or
  the shared `DomainRateLimiter` (LLM calls).
- **Secrets stay in `.env`**, which is git-ignored. Never commit keys or crawled data.

## Repository notes

- `crawler/data/` (raw archive, exports, extraction output) is git-ignored; it is large and
  contains third-party copyrighted text.
- `crawler/.superpowers/`, `.claude/`, virtualenvs and caches are git-ignored.
- `legacy/text-extractor/` is the original standalone extractor (FastAPI app, DNRTI-format
  output, custom-type editor). It is kept for reference and has its own README and tests
  (`pip install -r requirements.txt && python -m pytest`). Its extraction logic now lives in
  `crawler/src/crawler/extraction/`.
- `crawler/docs/superpowers/` holds the design specs and implementation plans written while
  building the project, named by date.
- History: both projects were imported with full commit history
  (`git log -- crawler`, `git log -- legacy/text-extractor`).

## Known gaps

- Extraction results are files only; the `records`, `actors`, `techniques` and `sectors` tables
  are reserved and unpopulated.
- Relations link entities within one sentence; pronouns are not resolved.
- Threat actor vs group, malware vs tool and technique vs pattern are left to the LLM.
- No evaluation set yet for entity/relation F1 (planned in `legacy/text-extractor/new plan.md`).
- No LICENSE file: choose one before making the repository public.

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

## Usage

```powershell
uv run crawler sources list
uv run crawler crawl --source kev
uv run crawler stats
```

## Tests

```powershell
uv run pytest
```

Tests never touch the network. Database tests need `TEST_DATABASE_URL` and are
skipped without it.

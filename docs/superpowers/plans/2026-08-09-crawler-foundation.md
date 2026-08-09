# Crawler Foundation Implementation Plan (Plan 1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the crawler foundation and prove it end-to-end by ingesting the CISA Known Exploited Vulnerabilities catalog into PostgreSQL.

**Architecture:** An async pipeline with pluggable source adapters. `core/` never imports a source; sources never touch the database. Adapters expose `discover()` (async, yields URLs) and `parse()` (sync, pure: bytes in, dataclasses out). The pipeline dedups by URL hash, archives raw bytes to disk, then persists parsed records.

**Tech Stack:** Python 3.12, uv, httpx, SQLAlchemy 2.0, Alembic, PostgreSQL 16, Typer, pydantic-settings, pytest + pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-08-09-cyber-threat-crawler-design.md`

## Global Constraints

- **Python 3.12+.** All dependencies managed by `uv`. Never use `pip install` or edit `pyproject.toml` dependency lists by hand — use `uv add`.
- **All commands run from PowerShell on Windows** at `C:\Project\Crawler`, except `docker compose`, which must run **from a WSL shell** (Docker lives in WSL2, no Docker Desktop).
- **Every timestamp is `timestamptz`, stored in UTC.** Never use naive datetimes. Use `datetime.now(timezone.utc)`.
- **No network access in tests.** Ever. Use fixtures and mock transports.
- **Database tests run against a real Postgres** database named `crawler_test`, wrapped in a rolled-back transaction per test. Do not use testcontainers — Docker is in WSL, pytest is on Windows.
- **Source adapters must not import from `crawler.db`.** The pipeline persists; adapters return dataclasses.
- **Line length 100, formatted and linted with `ruff`.**

## Refinement vs. the spec

The spec wrote the adapter contract as `parse(raw) -> ParsedDoc`. This plan uses **`parse(raw) -> list[ParsedDoc]`**. Reason: a single fetched file can contain many records (the KEV catalog is one JSON file holding ~1,200 vulnerabilities), while a news article yields exactly one. Returning a list covers both without a second code path.

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | uv project definition, dependencies, ruff + pytest config |
| `docker-compose.yml` | Postgres 16 service (run from WSL) |
| `.env.example` | Documented template for `DATABASE_URL`, `TEST_DATABASE_URL` |
| `src/crawler/config.py` | `Settings` loaded from `.env` via pydantic-settings |
| `src/crawler/cli.py` | Typer app; wires commands to pipeline |
| `src/crawler/core/models.py` | `DiscoveredItem`, `RawDocument`, `ParsedDoc`, `VulnerabilityFact` |
| `src/crawler/core/ratelimit.py` | Per-domain async rate limiter |
| `src/crawler/core/fetch.py` | Async HTTP client: retries, conditional requests, rate limiting |
| `src/crawler/core/archive.py` | Gzipped raw-document archive on disk |
| `src/crawler/core/pipeline.py` | Orchestration: discover → dedup → fetch → archive → parse → persist |
| `src/crawler/sources/base.py` | `Source` protocol + registry |
| `src/crawler/sources/kev.py` | CISA KEV adapter |
| `src/crawler/db/schema.py` | All SQLAlchemy models |
| `src/crawler/db/session.py` | Engine + session factory |
| `src/crawler/db/repo.py` | Upsert and query functions |
| `alembic/` | Migration environment and versions |
| `tests/` | Mirrors `src/`, plus `tests/fixtures/` |

---

### Task 1: Project scaffolding, config, and database container

**Files:**
- Create: `pyproject.toml`, `docker-compose.yml`, `.env.example`
- Create: `src/crawler/__init__.py`, `src/crawler/config.py`, `src/crawler/cli.py`
- Create: `src/crawler/core/__init__.py`, `src/crawler/sources/__init__.py`, `src/crawler/db/__init__.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `crawler.config.Settings` — pydantic-settings model with fields `database_url: str`, `test_database_url: str | None`, `raw_archive_dir: Path`, `user_agent: str`, `request_timeout: float`
  - `crawler.config.get_settings() -> Settings` — cached accessor
  - `crawler.cli.app` — Typer app; console script `crawler`

- [ ] **Step 1: Initialize the uv project and add dependencies**

```powershell
uv init --package --name crawler --python 3.12
uv add httpx sqlalchemy "psycopg[binary]" alembic typer pydantic-settings
uv add --dev pytest pytest-asyncio ruff
```

`--package` creates the `src/crawler/` layout. `psycopg[binary]` is psycopg 3 — do not use `psycopg2`.

- [ ] **Step 2: Configure pytest and ruff in `pyproject.toml`**

Append to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.ruff]
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[project.scripts]
crawler = "crawler.cli:app"
```

- [ ] **Step 3: Write the failing config test**

Create `tests/test_config.py`:

```python
from pathlib import Path

from crawler.config import Settings


def test_settings_read_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/crawler")
    monkeypatch.setenv("RAW_ARCHIVE_DIR", str(tmp_path / "raw"))

    settings = Settings()

    assert settings.database_url == "postgresql+psycopg://u:p@localhost:5432/crawler"
    assert settings.raw_archive_dir == Path(tmp_path / "raw")
    assert "crawler" in settings.user_agent.lower()


def test_user_agent_has_contact_info(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/crawler")

    settings = Settings()

    assert "+" in settings.user_agent or "@" in settings.user_agent
```

The second test enforces the politeness requirement that the User-Agent carries contact information.

- [ ] **Step 4: Run the test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.config'`

- [ ] **Step 5: Implement `src/crawler/config.py`**

```python
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    test_database_url: str | None = None
    raw_archive_dir: Path = Path("data/raw")
    user_agent: str = (
        "cyber-threat-crawler/0.1 (research crawler; +https://github.com/local/crawler)"
    )
    request_timeout: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/test_config.py -v`
Expected: 2 passed

- [ ] **Step 7: Create `docker-compose.yml`**

```yaml
services:
  db:
    image: postgres:16
    container_name: crawler-db
    environment:
      POSTGRES_USER: crawler
      POSTGRES_PASSWORD: crawler
      POSTGRES_DB: crawler
    ports:
      - "5432:5432"
    volumes:
      - crawler-pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U crawler"]
      interval: 5s
      timeout: 5s
      retries: 10

volumes:
  crawler-pgdata:
```

- [ ] **Step 8: Create `.env.example`**

```
# Postgres runs in Docker under WSL; reachable from Windows via localhost forwarding.
DATABASE_URL=postgresql+psycopg://crawler:crawler@localhost:5432/crawler

# Separate database used by the test suite. Create it once with:
#   docker exec crawler-db createdb -U crawler crawler_test
TEST_DATABASE_URL=postgresql+psycopg://crawler:crawler@localhost:5432/crawler_test

RAW_ARCHIVE_DIR=data/raw
```

- [ ] **Step 9: Start Postgres and create the test database**

**From a WSL shell**, in the project directory:

```bash
docker compose up -d
docker exec crawler-db createdb -U crawler crawler_test
```

Then, back in PowerShell: `Copy-Item .env.example .env`

- [ ] **Step 10: Write the `db ping` command in `src/crawler/cli.py`**

```python
import typer
from sqlalchemy import create_engine, text

from crawler.config import get_settings

app = typer.Typer(help="Cyber threat intelligence crawler.")
db_app = typer.Typer(help="Database operations.")
app.add_typer(db_app, name="db")


@db_app.command("ping")
def db_ping() -> None:
    """Verify the database is reachable."""
    settings = get_settings()
    try:
        engine = create_engine(settings.database_url)
        with engine.connect() as conn:
            version = conn.execute(text("SHOW server_version")).scalar()
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator verbatim
        typer.secho(f"FAILED: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    typer.secho(f"OK: PostgreSQL {version}", fg=typer.colors.GREEN)
```

- [ ] **Step 11: Verify the Windows-to-WSL database connection**

Run: `uv run crawler db ping`
Expected: `OK: PostgreSQL 16.x`

If this fails with a connection refused error, WSL2 localhost forwarding is the cause, not the code. Get the WSL IP with `wsl hostname -I` and use that host in `DATABASE_URL` instead of `localhost`.

- [ ] **Step 12: Commit**

```bash
git add pyproject.toml uv.lock docker-compose.yml .env.example src tests
git commit -m "feat: project scaffolding, settings, and db ping"
```

---

### Task 2: Database schema and migrations

**Files:**
- Create: `src/crawler/db/schema.py`, `src/crawler/db/session.py`
- Create: `alembic.ini`, `alembic/env.py`, `alembic/versions/<hash>_initial_schema.py`
- Create: `tests/conftest.py`, `tests/db/test_schema.py`
- Modify: `src/crawler/cli.py` (add `db upgrade`)

**Interfaces:**
- Consumes: `crawler.config.get_settings`
- Produces:
  - `crawler.db.schema.Base` — declarative base
  - Models: `Source`, `Document`, `Record`, `Vulnerability`, `CrawlRun`, `FetchError`, `Actor`, `Technique`, `Sector`, `AttackType`, `Ioc`, and junctions `DocumentCve`, `DocumentActor`, `DocumentTechnique`, `DocumentSector`, `DocumentAttackType`
  - `crawler.db.session.get_engine(url: str | None = None) -> Engine`
  - `crawler.db.session.session_scope() -> ContextManager[Session]`
  - `tests/conftest.py` fixture `db_session` — a `Session` in a transaction rolled back after each test

- [ ] **Step 1: Write the failing schema test**

Create `tests/db/test_schema.py`:

```python
from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from crawler.db.schema import Document, Source


def test_document_round_trips(db_session):
    db_session.add(Source(name="kev", kind="api", license="public-domain"))
    db_session.flush()

    doc = Document(
        source="kev",
        url="https://example.org/a",
        url_hash="hash-a",
        title="Example",
        body_text="body",
        fetched_at=datetime.now(timezone.utc),
        license="public-domain",
    )
    db_session.add(doc)
    db_session.flush()

    loaded = db_session.execute(select(Document).where(Document.url_hash == "hash-a")).scalar_one()
    assert loaded.title == "Example"
    assert loaded.fetched_at.tzinfo is not None


def test_url_hash_is_unique(db_session):
    db_session.add(Source(name="kev", kind="api", license="public-domain"))
    db_session.flush()

    for _ in range(2):
        db_session.add(
            Document(
                source="kev",
                url="https://example.org/dup",
                url_hash="same-hash",
                fetched_at=datetime.now(timezone.utc),
                license="public-domain",
            )
        )

    with pytest.raises(IntegrityError):
        db_session.flush()
```

- [ ] **Step 2: Write `tests/conftest.py`**

```python
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from crawler.db.schema import Base


@pytest.fixture(scope="session")
def engine():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set; skipping database tests")
    eng = create_engine(url)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def db_session(engine):
    """A session inside a transaction that is always rolled back."""
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
```

The rollback means tests never leave rows behind and can run in any order.

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/db -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.db.schema'`

- [ ] **Step 4: Implement `src/crawler/db/schema.py`**

```python
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JsonType = JSONB().with_variant(JSON(), "sqlite")


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    license: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(ForeignKey("sources.name"), index=True)
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), unique=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    title: Mapped[str | None] = mapped_column(Text)
    body_text: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw_path: Mapped[str | None] = mapped_column(Text)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    license: Mapped[str] = mapped_column(String(32))


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"))
    primary_attack_type: Mapped[str | None] = mapped_column(String(64), index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    extraction_version: Mapped[str] = mapped_column(String(32))
    extracted_by: Mapped[str] = mapped_column(String(16))
    extra: Mapped[dict | None] = mapped_column(JsonType)

    __table_args__ = (
        UniqueConstraint("document_id", "extraction_version", "extracted_by",
                         name="uq_record_version"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_v3: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    epss: Mapped[float | None] = mapped_column(Float)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)


class CrawlRun(Base):
    __tablename__ = "crawl_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    fetched: Mapped[int] = mapped_column(Integer, default=0)
    parsed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="running")
    note: Mapped[str | None] = mapped_column(Text)


class FetchError(Base):
    __tablename__ = "fetch_errors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(Text)
    error_class: Mapped[str] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    last_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("source", "url", name="uq_fetch_error_url"),)


class Actor(Base):
    __tablename__ = "actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    aliases: Mapped[dict | None] = mapped_column(JsonType)


class Technique(Base):
    __tablename__ = "techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # e.g. "T1566"
    name: Mapped[str] = mapped_column(Text)
    tactic: Mapped[str | None] = mapped_column(Text)


class Sector(Base):
    __tablename__ = "sectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)


class AttackType(Base):
    __tablename__ = "attack_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)


class Ioc(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(Text, index=True)

    __table_args__ = (UniqueConstraint("document_id", "type", "value", name="uq_ioc"),)


class DocumentCve(Base):
    __tablename__ = "document_cves"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True, index=True)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentActor(Base):
    __tablename__ = "document_actors"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("actors.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentTechnique(Base):
    __tablename__ = "document_techniques"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentSector(Base):
    __tablename__ = "document_sectors"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    sector_id: Mapped[int] = mapped_column(ForeignKey("sectors.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentAttackType(Base):
    __tablename__ = "document_attack_types"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    attack_type_id: Mapped[int] = mapped_column(ForeignKey("attack_types.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


Index("ix_documents_source_published", Document.source, Document.published_at)
```

Every `DateTime` is `timezone=True`, per the global constraints.

- [ ] **Step 5: Implement `src/crawler/db/session.py`**

```python
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from crawler.config import get_settings

_engine: Engine | None = None


def get_engine(url: str | None = None) -> Engine:
    global _engine
    if url is not None:
        return create_engine(url, pool_pre_ping=True)
    if _engine is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True)
    return _engine


@contextmanager
def session_scope(url: str | None = None) -> Iterator[Session]:
    factory = sessionmaker(bind=get_engine(url), expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/db -v`
Expected: 2 passed

- [ ] **Step 7: Initialize Alembic**

```powershell
uv run alembic init alembic
```

Use the **default** (synchronous) template, not `-t async`. The engine in `session.py` is a
sync psycopg engine; the async template would fail against it.

Then edit `alembic/env.py` — replace its `target_metadata = None` line and URL handling:

```python
from crawler.config import get_settings
from crawler.db.schema import Base

target_metadata = Base.metadata
config.set_main_option("sqlalchemy.url", get_settings().database_url)
```

- [ ] **Step 8: Generate and apply the initial migration**

```powershell
uv run alembic revision --autogenerate -m "initial schema"
uv run alembic upgrade head
```

- [ ] **Step 9: Verify the tables exist**

**From WSL:** `docker exec crawler-db psql -U crawler -d crawler -c "\dt"`
Expected: 16 application tables plus `alembic_version`, including `documents`, `records`,
`vulnerabilities`, and `crawl_runs`.

- [ ] **Step 10: Add `db upgrade` to the CLI**

Add to `src/crawler/cli.py`:

```python
@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply all pending database migrations."""
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")
    typer.secho("Migrations applied.", fg=typer.colors.GREEN)
```

- [ ] **Step 11: Commit**

```bash
git add src/crawler/db alembic alembic.ini tests src/crawler/cli.py
git commit -m "feat: database schema, session handling, and migrations"
```

---

### Task 3: Core dataclasses and the Source protocol

**Files:**
- Create: `src/crawler/core/models.py`, `src/crawler/sources/base.py`
- Test: `tests/core/test_models.py`, `tests/sources/test_registry.py`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `crawler.core.models.DiscoveredItem(url, source, published_at=None, title=None, hint=None)` with property `url_hash: str` (sha256 hex of the URL)
  - `crawler.core.models.RawDocument(item, content: bytes, content_type, http_status, fetched_at, etag=None, last_modified=None)` with property `content_hash: str`
  - `crawler.core.models.VulnerabilityFact(cve_id, vendor=None, product=None, description=None, kev_listed=False, kev_added_date=None, published=None)`
  - `crawler.core.models.ParsedDoc(url, source, title, body_text, license, published_at=None, vulnerabilities=(), warnings=())`
  - `crawler.sources.base.Source` — Protocol with `name`, `kind`, `license`, `rate_limit`, `async discover(since)`, `parse(raw) -> list[ParsedDoc]`
  - `crawler.sources.base.RateLimit(requests: int, per_seconds: float)`
  - `crawler.sources.base.register(source)` / `get_source(name)` / `all_sources()`

- [ ] **Step 1: Write the failing models test**

Create `tests/core/test_models.py`:

```python
from datetime import datetime, timezone

from crawler.core.models import DiscoveredItem, RawDocument


def test_url_hash_is_stable_and_unique():
    a = DiscoveredItem(url="https://example.org/a", source="kev")
    b = DiscoveredItem(url="https://example.org/a", source="kev")
    c = DiscoveredItem(url="https://example.org/b", source="kev")

    assert a.url_hash == b.url_hash
    assert a.url_hash != c.url_hash
    assert len(a.url_hash) == 64


def test_content_hash_detects_change():
    item = DiscoveredItem(url="https://example.org/a", source="kev")
    common = dict(
        item=item,
        content_type="application/json",
        http_status=200,
        fetched_at=datetime.now(timezone.utc),
    )

    same_a = RawDocument(content=b"hello", **common)
    same_b = RawDocument(content=b"hello", **common)
    different = RawDocument(content=b"goodbye", **common)

    assert same_a.content_hash == same_b.content_hash
    assert same_a.content_hash != different.content_hash
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/core/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.core.models'`

- [ ] **Step 3: Implement `src/crawler/core/models.py`**

```python
import hashlib
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class DiscoveredItem:
    """A URL a source wants fetched, plus anything the source already knows about it."""

    url: str
    source: str
    published_at: datetime | None = None
    title: str | None = None
    hint: dict = field(default_factory=dict)

    @property
    def url_hash(self) -> str:
        return hashlib.sha256(self.url.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RawDocument:
    """Bytes as fetched, before any parsing."""

    item: DiscoveredItem
    content: bytes
    content_type: str
    http_status: int
    fetched_at: datetime
    etag: str | None = None
    last_modified: str | None = None

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class VulnerabilityFact:
    """A CVE-level fact asserted by a source."""

    cve_id: str
    vendor: str | None = None
    product: str | None = None
    description: str | None = None
    kev_listed: bool = False
    kev_added_date: datetime | None = None
    published: datetime | None = None


@dataclass(frozen=True)
class ParsedDoc:
    """One logical document extracted from a raw fetch."""

    url: str
    source: str
    title: str
    body_text: str
    license: str
    published_at: datetime | None = None
    vulnerabilities: tuple[VulnerabilityFact, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def url_hash(self) -> str:
        return hashlib.sha256(self.url.encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/core/test_models.py -v`
Expected: 2 passed

- [ ] **Step 5: Write the failing registry test**

Create `tests/sources/test_registry.py`:

```python
import pytest

from crawler.sources.base import RateLimit, all_sources, get_source, register


class _Fake:
    name = "fake"
    kind = "api"
    license = "public-domain"
    rate_limit = RateLimit(requests=1, per_seconds=1.0)

    async def discover(self, since):
        yield None

    def parse(self, raw):
        return []


def test_register_and_retrieve():
    source = _Fake()
    register(source)

    assert get_source("fake") is source
    assert source in all_sources()


def test_unknown_source_raises():
    with pytest.raises(KeyError, match="unknown"):
        get_source("unknown")
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `uv run pytest tests/sources/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.sources.base'`

- [ ] **Step 7: Implement `src/crawler/sources/base.py`**

```python
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from crawler.core.models import DiscoveredItem, ParsedDoc, RawDocument


@dataclass(frozen=True)
class RateLimit:
    requests: int
    per_seconds: float


@runtime_checkable
class Source(Protocol):
    name: str
    kind: Literal["feed", "api", "html", "pdf"]
    license: str
    rate_limit: RateLimit

    def discover(self, since: datetime) -> AsyncIterator[DiscoveredItem]:
        """Yield items to fetch that may have changed since `since`."""
        ...

    def parse(self, raw: RawDocument) -> list[ParsedDoc]:
        """Pure function: bytes in, documents out. No network, no database."""
        ...


_REGISTRY: dict[str, Source] = {}


def register(source: Source) -> Source:
    _REGISTRY[source.name] = source
    return source


def get_source(name: str) -> Source:
    if name not in _REGISTRY:
        raise KeyError(f"unknown source: {name!r}")
    return _REGISTRY[name]


def all_sources() -> list[Source]:
    return list(_REGISTRY.values())
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run pytest tests/sources tests/core -v`
Expected: 4 passed

- [ ] **Step 9: Commit**

```bash
git add src/crawler/core/models.py src/crawler/sources/base.py tests
git commit -m "feat: core dataclasses and source protocol with registry"
```

---

### Task 4: Rate limiter

**Files:**
- Create: `src/crawler/core/ratelimit.py`
- Test: `tests/core/test_ratelimit.py`

**Interfaces:**
- Consumes: `crawler.sources.base.RateLimit`
- Produces:
  - `crawler.core.ratelimit.DomainRateLimiter(default: RateLimit, clock=None, sleep=None)`
  - `async DomainRateLimiter.acquire(url: str) -> None` — blocks until a request to that URL's host is permitted
  - `DomainRateLimiter.set_limit(host: str, limit: RateLimit) -> None`

The injectable `clock` and `sleep` are what make this testable without real waiting. Default to `time.monotonic` and `asyncio.sleep`.

- [ ] **Step 1: Write the failing test**

Create `tests/core/test_ratelimit.py`:

```python
from crawler.core.ratelimit import DomainRateLimiter
from crawler.sources.base import RateLimit


class FakeClock:
    """Deterministic clock: sleeping advances time instead of waiting."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


async def test_second_request_to_same_host_waits():
    clock = FakeClock()
    limiter = DomainRateLimiter(
        default=RateLimit(requests=1, per_seconds=2.0), clock=clock.time, sleep=clock.sleep
    )

    await limiter.acquire("https://example.org/a")
    await limiter.acquire("https://example.org/b")

    assert clock.slept == [2.0]


async def test_different_hosts_do_not_block_each_other():
    clock = FakeClock()
    limiter = DomainRateLimiter(
        default=RateLimit(requests=1, per_seconds=2.0), clock=clock.time, sleep=clock.sleep
    )

    await limiter.acquire("https://a.example/x")
    await limiter.acquire("https://b.example/y")

    assert clock.slept == []


async def test_per_host_override_is_used():
    clock = FakeClock()
    limiter = DomainRateLimiter(
        default=RateLimit(requests=1, per_seconds=1.0), clock=clock.time, sleep=clock.sleep
    )
    limiter.set_limit("slow.example", RateLimit(requests=1, per_seconds=6.0))

    await limiter.acquire("https://slow.example/a")
    await limiter.acquire("https://slow.example/b")

    assert clock.slept == [6.0]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/core/test_ratelimit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.core.ratelimit'`

- [ ] **Step 3: Implement `src/crawler/core/ratelimit.py`**

```python
import asyncio
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from crawler.sources.base import RateLimit


class DomainRateLimiter:
    """Enforces `requests per per_seconds` independently for each host."""

    def __init__(
        self,
        default: RateLimit,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._default = default
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._limits: dict[str, RateLimit] = {}
        self._recent: dict[str, list[float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def set_limit(self, host: str, limit: RateLimit) -> None:
        self._limits[host] = limit

    async def acquire(self, url: str) -> None:
        host = urlparse(url).netloc
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            limit = self._limits.get(host, self._default)
            window = self._recent.setdefault(host, [])
            now = self._clock()

            cutoff = now - limit.per_seconds
            window[:] = [t for t in window if t > cutoff]

            if len(window) >= limit.requests:
                wait = window[0] + limit.per_seconds - now
                if wait > 0:
                    await self._sleep(wait)
                    now = self._clock()
                    cutoff = now - limit.per_seconds
                    window[:] = [t for t in window if t > cutoff]

            window.append(now)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_ratelimit.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/crawler/core/ratelimit.py tests/core/test_ratelimit.py
git commit -m "feat: per-domain rate limiter with injectable clock"
```

---

### Task 5: Fetch client with retries, conditional requests, and robots.txt

**Files:**
- Create: `src/crawler/core/fetch.py`
- Test: `tests/core/test_fetch.py`

**Interfaces:**
- Consumes: `DiscoveredItem`, `RawDocument`, `DomainRateLimiter`, `RateLimit`, `get_settings`
- Produces:
  - `crawler.core.fetch.Fetcher(client: httpx.AsyncClient, limiter: DomainRateLimiter, user_agent: str, max_attempts: int = 4, sleep=None)`
  - `async Fetcher.fetch(item, etag=None, last_modified=None) -> RawDocument | None` — returns `None` on HTTP 304 (unchanged)
  - `crawler.core.fetch.PermanentFetchError` (404/410, never retried)
  - `crawler.core.fetch.TransientFetchError` (raised after retries are exhausted)
  - `crawler.core.fetch.RobotsDisallowed` (URL forbidden by `robots.txt`)
  - `crawler.core.fetch.RobotsCache(client, user_agent)` with `async allowed(url) -> bool`

- [ ] **Step 1: Write the failing test**

Create `tests/core/test_fetch.py`:

```python
import httpx
import pytest

from crawler.core.fetch import Fetcher, PermanentFetchError, TransientFetchError
from crawler.core.models import DiscoveredItem
from crawler.core.ratelimit import DomainRateLimiter
from crawler.sources.base import RateLimit

ITEM = DiscoveredItem(url="https://example.org/a", source="test")


def make_fetcher(handler, slept: list[float]):
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = DomainRateLimiter(
        default=RateLimit(requests=100, per_seconds=1.0), sleep=fake_sleep
    )
    return Fetcher(client=client, limiter=limiter, user_agent="test-agent", sleep=fake_sleep)


async def test_successful_fetch_returns_raw_document():
    def handler(request):
        assert request.headers["user-agent"] == "test-agent"
        return httpx.Response(200, content=b'{"ok": true}',
                              headers={"content-type": "application/json", "etag": "W/\"v1\""})

    raw = await make_fetcher(handler, []).fetch(ITEM)

    assert raw is not None
    assert raw.content == b'{"ok": true}'
    assert raw.etag == 'W/"v1"'
    assert raw.http_status == 200


async def test_304_returns_none_and_sends_conditional_headers():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(304)

    raw = await make_fetcher(handler, []).fetch(ITEM, etag='W/"v1"', last_modified="Mon, 01 Jan 2024 00:00:00 GMT")

    assert raw is None
    assert seen["if-none-match"] == 'W/"v1"'
    assert seen["if-modified-since"] == "Mon, 01 Jan 2024 00:00:00 GMT"


async def test_404_raises_permanent_without_retrying():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(404)

    with pytest.raises(PermanentFetchError):
        await make_fetcher(handler, []).fetch(ITEM)

    assert len(calls) == 1


async def test_429_retries_with_backoff_then_succeeds():
    calls = []
    slept: list[float] = []

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(429, headers={"retry-after": "7"})
        return httpx.Response(200, content=b"ok", headers={"content-type": "text/plain"})

    raw = await make_fetcher(handler, slept).fetch(ITEM)

    assert raw is not None
    assert len(calls) == 3
    assert slept[:2] == [7.0, 7.0]  # Retry-After honoured over computed backoff


async def test_persistent_500_raises_transient_after_max_attempts():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(500)

    with pytest.raises(TransientFetchError):
        await make_fetcher(handler, []).fetch(ITEM)

    assert len(calls) == 4
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_fetch.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.core.fetch'`

- [ ] **Step 3: Implement `src/crawler/core/fetch.py`**

```python
import asyncio
import random
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

import httpx

from crawler.core.models import DiscoveredItem, RawDocument
from crawler.core.ratelimit import DomainRateLimiter

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
PERMANENT_STATUS = {400, 401, 403, 404, 410}


class FetchError(Exception):
    pass


class PermanentFetchError(FetchError):
    """Do not retry: the resource is gone or forbidden."""


class TransientFetchError(FetchError):
    """Retries were exhausted; the URL may succeed later."""


class Fetcher:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: DomainRateLimiter,
        user_agent: str,
        max_attempts: int = 4,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._user_agent = user_agent
        self._max_attempts = max_attempts
        self._sleep = sleep or asyncio.sleep

    async def fetch(
        self,
        item: DiscoveredItem,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> RawDocument | None:
        headers = {"user-agent": self._user_agent}
        if etag:
            headers["if-none-match"] = etag
        if last_modified:
            headers["if-modified-since"] = last_modified

        last_error: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            await self._limiter.acquire(item.url)
            try:
                response = await self._client.get(
                    item.url, headers=headers, follow_redirects=True
                )
            except httpx.HTTPError as exc:
                last_error = exc
                await self._backoff(attempt, None)
                continue

            if response.status_code == 304:
                return None

            if response.status_code in PERMANENT_STATUS:
                raise PermanentFetchError(f"{response.status_code} for {item.url}")

            if response.status_code in RETRYABLE_STATUS:
                last_error = TransientFetchError(f"{response.status_code} for {item.url}")
                if attempt < self._max_attempts:
                    await self._backoff(attempt, response.headers.get("retry-after"))
                continue

            response.raise_for_status()
            return RawDocument(
                item=item,
                content=response.content,
                content_type=response.headers.get("content-type", ""),
                http_status=response.status_code,
                fetched_at=datetime.now(timezone.utc),
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
            )

        raise TransientFetchError(f"gave up on {item.url} after {self._max_attempts} attempts") \
            from last_error

    async def _backoff(self, attempt: int, retry_after: str | None) -> None:
        """Honour Retry-After when present, otherwise exponential backoff with jitter."""
        if retry_after:
            try:
                await self._sleep(float(retry_after))
                return
            except ValueError:
                pass  # Retry-After may be an HTTP date; fall through to backoff
        await self._sleep(min(60.0, 2 ** attempt) + random.uniform(0, 0.5))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_fetch.py -v`
Expected: 5 passed

- [ ] **Step 5: Write the failing robots.txt test**

Append to `tests/core/test_fetch.py`:

```python
from crawler.core.fetch import RobotsCache, RobotsDisallowed

ROBOTS = b"""
User-agent: *
Disallow: /private/
"""


def robots_handler(fetched: list[str]):
    def handler(request):
        if request.url.path == "/robots.txt":
            fetched.append(str(request.url))
            return httpx.Response(200, content=ROBOTS, headers={"content-type": "text/plain"})
        return httpx.Response(200, content=b"page", headers={"content-type": "text/html"})

    return handler


async def test_robots_allows_permitted_path():
    client = httpx.AsyncClient(transport=httpx.MockTransport(robots_handler([])))
    robots = RobotsCache(client=client, user_agent="test-agent")

    assert await robots.allowed("https://example.org/public/a") is True


async def test_robots_blocks_disallowed_path():
    client = httpx.AsyncClient(transport=httpx.MockTransport(robots_handler([])))
    robots = RobotsCache(client=client, user_agent="test-agent")

    assert await robots.allowed("https://example.org/private/secret") is False


async def test_robots_is_fetched_once_per_host():
    fetched: list[str] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(robots_handler(fetched)))
    robots = RobotsCache(client=client, user_agent="test-agent")

    await robots.allowed("https://example.org/a")
    await robots.allowed("https://example.org/b")

    assert len(fetched) == 1


async def test_missing_robots_allows_everything():
    def handler(request):
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, content=b"page")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    robots = RobotsCache(client=client, user_agent="test-agent")

    assert await robots.allowed("https://example.org/anything") is True


async def test_fetcher_raises_when_robots_disallows():
    fetcher = make_fetcher(robots_handler([]), [])
    fetcher.robots = RobotsCache(
        client=httpx.AsyncClient(transport=httpx.MockTransport(robots_handler([]))),
        user_agent="test-agent",
    )

    with pytest.raises(RobotsDisallowed):
        await fetcher.fetch(DiscoveredItem(url="https://example.org/private/x", source="test"))
```

A missing `robots.txt` means "no restrictions" — treating a 404 as "block everything" would
silently stop the crawler on most sites.

- [ ] **Step 6: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_fetch.py -v`
Expected: FAIL with `ImportError: cannot import name 'RobotsCache'`

- [ ] **Step 7: Add robots support to `src/crawler/core/fetch.py`**

Add these imports at the top:

```python
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser
```

Add the exception alongside the others:

```python
class RobotsDisallowed(FetchError):
    """The site's robots.txt forbids fetching this URL."""
```

Add the cache class:

```python
class RobotsCache:
    """Fetches and caches robots.txt per host. A missing file means everything is allowed."""

    def __init__(self, client: httpx.AsyncClient, user_agent: str) -> None:
        self._client = client
        self._user_agent = user_agent
        self._parsers: dict[str, RobotFileParser | None] = {}

    async def allowed(self, url: str) -> bool:
        parts = urlparse(url)
        host = parts.netloc
        if host not in self._parsers:
            self._parsers[host] = await self._load(f"{parts.scheme}://{host}/robots.txt")
        parser = self._parsers[host]
        if parser is None:
            return True
        return parser.can_fetch(self._user_agent, url)

    async def _load(self, robots_url: str) -> RobotFileParser | None:
        try:
            response = await self._client.get(
                robots_url, headers={"user-agent": self._user_agent}
            )
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser
```

Give `Fetcher.__init__` a `robots` parameter defaulting to `None`, stored as `self.robots`,
and add this as the **first** statement in `Fetcher.fetch`, before the header setup:

```python
        if self.robots is not None and not await self.robots.allowed(item.url):
            raise RobotsDisallowed(f"robots.txt forbids {item.url}")
```

`RobotsDisallowed` subclasses `FetchError`, so the pipeline's existing handler records it in
`fetch_errors` and moves on — no pipeline change needed. But because a blocked URL counts
toward the circuit breaker, a site that blocks the crawler entirely will quarantine itself
after 5 URLs rather than grinding through thousands.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_fetch.py -v`
Expected: 10 passed

- [ ] **Step 9: Commit**

```bash
git add src/crawler/core/fetch.py tests/core/test_fetch.py
git commit -m "feat: async fetcher with retries, conditional requests, and robots.txt"
```

---

### Task 6: Raw document archive

**Files:**
- Create: `src/crawler/core/archive.py`
- Test: `tests/core/test_archive.py`

**Interfaces:**
- Consumes: `RawDocument`
- Produces:
  - `crawler.core.archive.RawArchive(root: Path)`
  - `RawArchive.store(raw: RawDocument) -> str` — writes gzip, returns the path relative to root
  - `RawArchive.load(relative_path: str) -> bytes`

Layout is `<source>/<yyyy>/<mm>/<url_hash>.<ext>.gz`, partitioned by fetch date. The extension comes from the content type so a later `reparse` knows whether it holds HTML, JSON, or PDF.

- [ ] **Step 1: Write the failing test**

Create `tests/core/test_archive.py`:

```python
from datetime import datetime, timezone

from crawler.core.archive import RawArchive
from crawler.core.models import DiscoveredItem, RawDocument


def make_raw(content: bytes, content_type: str) -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(url="https://example.org/a", source="kev"),
        content=content,
        content_type=content_type,
        http_status=200,
        fetched_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )


def test_store_then_load_round_trips(tmp_path):
    archive = RawArchive(tmp_path)
    raw = make_raw(b'{"a": 1}', "application/json")

    path = archive.store(raw)

    assert archive.load(path) == b'{"a": 1}'


def test_path_is_partitioned_by_source_and_date(tmp_path):
    archive = RawArchive(tmp_path)

    path = archive.store(make_raw(b"x", "text/html; charset=utf-8"))

    assert path.startswith("kev/2026/03/")
    assert path.endswith(".html.gz")


def test_extension_follows_content_type(tmp_path):
    archive = RawArchive(tmp_path)

    assert archive.store(make_raw(b"x", "application/json")).endswith(".json.gz")
    assert archive.store(make_raw(b"y", "application/pdf")).endswith(".pdf.gz")
    assert archive.store(make_raw(b"z", "application/octet-stream")).endswith(".bin.gz")


def test_storing_twice_is_idempotent(tmp_path):
    archive = RawArchive(tmp_path)
    raw = make_raw(b"same", "text/html")

    assert archive.store(raw) == archive.store(raw)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_archive.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.core.archive'`

- [ ] **Step 3: Implement `src/crawler/core/archive.py`**

```python
import gzip
from pathlib import Path

from crawler.core.models import RawDocument

_EXTENSIONS = {
    "text/html": "html",
    "application/xhtml+xml": "html",
    "application/json": "json",
    "text/json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "application/rss+xml": "xml",
    "application/pdf": "pdf",
    "text/csv": "csv",
    "text/plain": "txt",
}


class RawArchive:
    """Gzipped on-disk store of fetched bytes, so parsing can be redone without re-crawling."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def store(self, raw: RawDocument) -> str:
        relative = self._relative_path(raw)
        target = self._root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(gzip.compress(raw.content))
        return relative

    def load(self, relative_path: str) -> bytes:
        return gzip.decompress((self._root / relative_path).read_bytes())

    def _relative_path(self, raw: RawDocument) -> str:
        mime = raw.content_type.split(";")[0].strip().lower()
        ext = _EXTENSIONS.get(mime, "bin")
        stamp = raw.fetched_at
        return (
            f"{raw.item.source}/{stamp:%Y}/{stamp:%m}/{raw.item.url_hash}.{ext}.gz"
        )
```

`store` uses forward slashes in the returned string so archive paths stay portable if the data ever moves to Linux.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_archive.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/crawler/core/archive.py tests/core/test_archive.py
git commit -m "feat: gzipped raw document archive"
```

---

### Task 7: Repository layer

**Files:**
- Create: `src/crawler/db/repo.py`
- Test: `tests/db/test_repo.py`

**Interfaces:**
- Consumes: `crawler.db.schema` models, `ParsedDoc`, `RawDocument`
- Produces:
  - `repo.ensure_source(session, name, kind, license) -> Source`
  - `repo.get_document_by_url_hash(session, url_hash) -> Document | None`
  - `repo.upsert_document(session, parsed, raw, raw_path) -> tuple[Document, bool]` — bool is `True` when newly created
  - `repo.upsert_vulnerability(session, fact) -> None`
  - `repo.start_run(session, source) -> CrawlRun`
  - `repo.finish_run(session, run, status, note=None) -> None`
  - `repo.record_fetch_error(session, source, url, error_class, message) -> None`
  - `repo.mark_source_success(session, name, when) -> None`

- [ ] **Step 1: Write the failing test**

Create `tests/db/test_repo.py`:

```python
from datetime import datetime, timezone

from sqlalchemy import select

from crawler.core.models import DiscoveredItem, ParsedDoc, RawDocument, VulnerabilityFact
from crawler.db import repo
from crawler.db.schema import Document, FetchError, Vulnerability

NOW = datetime(2026, 3, 15, tzinfo=timezone.utc)


def make_parsed(url: str = "https://example.org/a", title: str = "T") -> ParsedDoc:
    return ParsedDoc(
        url=url, source="kev", title=title, body_text="body", license="public-domain"
    )


def make_raw(url: str = "https://example.org/a", content: bytes = b"x") -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(url=url, source="kev"),
        content=content,
        content_type="application/json",
        http_status=200,
        fetched_at=NOW,
        etag='W/"v1"',
    )


def test_upsert_document_inserts_then_updates(db_session):
    repo.ensure_source(db_session, "kev", "api", "public-domain")

    doc, created = repo.upsert_document(db_session, make_parsed(), make_raw(), "kev/p.json.gz")
    db_session.flush()
    assert created is True
    assert doc.title == "T"

    doc2, created2 = repo.upsert_document(
        db_session, make_parsed(title="Updated"), make_raw(content=b"y"), "kev/p2.json.gz"
    )
    db_session.flush()

    assert created2 is False
    assert doc2.id == doc.id
    assert doc2.title == "Updated"
    assert len(db_session.execute(select(Document)).scalars().all()) == 1


def test_upsert_vulnerability_merges_fields(db_session):
    repo.upsert_vulnerability(db_session, VulnerabilityFact(cve_id="CVE-2024-0001", vendor="Acme"))
    db_session.flush()
    repo.upsert_vulnerability(
        db_session, VulnerabilityFact(cve_id="CVE-2024-0001", kev_listed=True, product="Widget")
    )
    db_session.flush()

    vuln = db_session.get(Vulnerability, "CVE-2024-0001")
    assert vuln.vendor == "Acme"
    assert vuln.product == "Widget"
    assert vuln.kev_listed is True


def test_record_fetch_error_increments_attempts(db_session):
    repo.record_fetch_error(db_session, "kev", "https://example.org/x", "TransientFetchError", "500")
    db_session.flush()
    repo.record_fetch_error(db_session, "kev", "https://example.org/x", "TransientFetchError", "500")
    db_session.flush()

    error = db_session.execute(select(FetchError)).scalar_one()
    assert error.attempts == 2


def test_run_lifecycle(db_session):
    repo.ensure_source(db_session, "kev", "api", "public-domain")
    run = repo.start_run(db_session, "kev")
    db_session.flush()
    assert run.status == "running"

    run.discovered = 5
    repo.finish_run(db_session, run, "ok")
    db_session.flush()

    assert run.status == "ok"
    assert run.finished_at is not None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/db/test_repo.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.db.repo'`

- [ ] **Step 3: Implement `src/crawler/db/repo.py`**

```python
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from crawler.core.models import ParsedDoc, RawDocument, VulnerabilityFact
from crawler.db.schema import CrawlRun, Document, FetchError, Source, Vulnerability


def ensure_source(session: Session, name: str, kind: str, license: str) -> Source:
    source = session.get(Source, name)
    if source is None:
        source = Source(name=name, kind=kind, license=license)
        session.add(source)
    return source


def get_document_by_url_hash(session: Session, url_hash: str) -> Document | None:
    return session.execute(
        select(Document).where(Document.url_hash == url_hash)
    ).scalar_one_or_none()


def upsert_document(
    session: Session, parsed: ParsedDoc, raw: RawDocument, raw_path: str | None
) -> tuple[Document, bool]:
    existing = get_document_by_url_hash(session, parsed.url_hash)
    created = existing is None
    doc = existing or Document(
        source=parsed.source, url=parsed.url, url_hash=parsed.url_hash, license=parsed.license
    )

    doc.title = parsed.title
    doc.body_text = parsed.body_text
    doc.published_at = parsed.published_at
    doc.fetched_at = raw.fetched_at
    doc.content_hash = raw.content_hash
    doc.http_status = raw.http_status
    doc.etag = raw.etag
    doc.last_modified = raw.last_modified
    doc.raw_path = raw_path

    if created:
        session.add(doc)
    return doc, created


def upsert_vulnerability(session: Session, fact: VulnerabilityFact) -> None:
    vuln = session.get(Vulnerability, fact.cve_id)
    if vuln is None:
        vuln = Vulnerability(cve_id=fact.cve_id)
        session.add(vuln)

    # Only overwrite with values the source actually asserted.
    for field in ("vendor", "product", "description", "published", "kev_added_date"):
        value = getattr(fact, field)
        if value is not None:
            setattr(vuln, field, value)
    if fact.kev_listed:
        vuln.kev_listed = True


def start_run(session: Session, source: str) -> CrawlRun:
    run = CrawlRun(source=source, started_at=datetime.now(timezone.utc), status="running")
    session.add(run)
    return run


def finish_run(session: Session, run: CrawlRun, status: str, note: str | None = None) -> None:
    run.finished_at = datetime.now(timezone.utc)
    run.status = status
    run.note = note


def record_fetch_error(
    session: Session, source: str, url: str, error_class: str, message: str | None
) -> None:
    existing = session.execute(
        select(FetchError).where(FetchError.source == source, FetchError.url == url)
    ).scalar_one_or_none()

    if existing is None:
        session.add(
            FetchError(
                source=source,
                url=url,
                error_class=error_class,
                message=message,
                attempts=1,
                last_attempt_at=datetime.now(timezone.utc),
            )
        )
        return

    existing.attempts += 1
    existing.error_class = error_class
    existing.message = message
    existing.last_attempt_at = datetime.now(timezone.utc)


def mark_source_success(session: Session, name: str, when: datetime) -> None:
    source = session.get(Source, name)
    if source is not None:
        source.last_success_at = when
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/db -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/crawler/db/repo.py tests/db/test_repo.py
git commit -m "feat: repository layer for documents, vulnerabilities, runs, and errors"
```

---

### Task 8: Pipeline orchestration

**Files:**
- Create: `src/crawler/core/pipeline.py`
- Test: `tests/core/test_pipeline.py`

**Interfaces:**
- Consumes: `Source`, `Fetcher`, `RawArchive`, `repo`, `session_scope`
- Produces:
  - `crawler.core.pipeline.run_source(source, fetcher, archive, session, since) -> CrawlRun`
  - `crawler.core.pipeline.CIRCUIT_BREAKER_THRESHOLD = 5`

Behaviour contract, all covered by the tests below:
1. Skip items whose `url_hash` already exists **and** whose stored `content_hash` is unchanged — passing the stored `etag`/`last_modified` so the server can answer 304.
2. A `PermanentFetchError` on one item is recorded and skipped; the run continues.
3. After 5 consecutive failures the source is quarantined: the run stops with status `circuit_open`.
4. Counters on `CrawlRun` reflect what happened.

- [ ] **Step 1: Write the failing test**

Create `tests/core/test_pipeline.py`:

```python
from datetime import datetime, timezone

import pytest

from crawler.core.fetch import PermanentFetchError
from crawler.core.models import DiscoveredItem, ParsedDoc, RawDocument
from crawler.core.pipeline import run_source
from crawler.db import repo
from crawler.sources.base import RateLimit

NOW = datetime(2026, 3, 15, tzinfo=timezone.utc)


class StubSource:
    name = "stub"
    kind = "api"
    license = "public-domain"
    rate_limit = RateLimit(requests=100, per_seconds=1.0)

    def __init__(self, urls):
        self._urls = urls

    async def discover(self, since):
        for url in self._urls:
            yield DiscoveredItem(url=url, source=self.name)

    def parse(self, raw):
        return [
            ParsedDoc(
                url=raw.item.url,
                source=self.name,
                title=f"Doc {raw.item.url}",
                body_text=raw.content.decode(),
                license=self.license,
            )
        ]


class StubFetcher:
    """Returns a canned result per URL: bytes, an exception, or None for 304."""

    def __init__(self, results):
        self._results = results
        self.conditional_headers = []

    async def fetch(self, item, etag=None, last_modified=None):
        self.conditional_headers.append((item.url, etag, last_modified))
        result = self._results[item.url]
        if isinstance(result, Exception):
            raise result
        if result is None:
            return None
        return RawDocument(
            item=item,
            content=result,
            content_type="application/json",
            http_status=200,
            fetched_at=NOW,
            etag='W/"v1"',
        )


class StubArchive:
    def __init__(self):
        self.stored = []

    def store(self, raw):
        self.stored.append(raw.item.url)
        return f"stub/{raw.item.url_hash}.json.gz"


async def test_happy_path_persists_documents(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    source = StubSource(["https://example.org/1", "https://example.org/2"])
    fetcher = StubFetcher({"https://example.org/1": b"one", "https://example.org/2": b"two"})
    archive = StubArchive()

    run = await run_source(source, fetcher, archive, db_session, since=NOW)

    assert run.discovered == 2
    assert run.fetched == 2
    assert run.parsed == 2
    assert run.failed == 0
    assert run.status == "ok"
    assert archive.stored == ["https://example.org/1", "https://example.org/2"]


async def test_unchanged_document_sends_conditional_headers_and_is_skipped(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    url = "https://example.org/1"

    first_source = StubSource([url])
    first_fetcher = StubFetcher({url: b"one"})
    await run_source(first_source, first_fetcher, StubArchive(), db_session, since=NOW)
    db_session.flush()

    second_fetcher = StubFetcher({url: None})  # server answers 304
    run = await run_source(StubSource([url]), second_fetcher, StubArchive(), db_session, since=NOW)

    assert second_fetcher.conditional_headers == [(url, 'W/"v1"', None)]
    assert run.fetched == 0
    assert run.parsed == 0
    assert run.status == "ok"


async def test_permanent_error_is_recorded_and_run_continues(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    source = StubSource(["https://example.org/gone", "https://example.org/ok"])
    fetcher = StubFetcher({
        "https://example.org/gone": PermanentFetchError("404"),
        "https://example.org/ok": b"fine",
    })

    run = await run_source(source, fetcher, StubArchive(), db_session, since=NOW)

    assert run.failed == 1
    assert run.parsed == 1
    assert run.status == "ok"


async def test_circuit_breaker_opens_after_five_consecutive_failures(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    urls = [f"https://example.org/{i}" for i in range(10)]
    source = StubSource(urls)
    fetcher = StubFetcher({url: PermanentFetchError("404") for url in urls})

    run = await run_source(source, fetcher, StubArchive(), db_session, since=NOW)

    assert run.status == "circuit_open"
    assert run.failed == 5
    assert len(fetcher.conditional_headers) == 5  # stopped early
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_pipeline.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.core.pipeline'`

- [ ] **Step 3: Implement `src/crawler/core/pipeline.py`**

```python
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from crawler.core.fetch import FetchError
from crawler.db import repo
from crawler.db.schema import CrawlRun

logger = logging.getLogger(__name__)

CIRCUIT_BREAKER_THRESHOLD = 5
COMMIT_EVERY = 50


async def run_source(source, fetcher, archive, session: Session, since: datetime) -> CrawlRun:
    """Discover, fetch, archive, parse, and persist everything one source offers."""
    repo.ensure_source(session, source.name, source.kind, source.license)
    run = repo.start_run(session, source.name)
    session.flush()

    consecutive_failures = 0
    processed_since_commit = 0
    status = "ok"

    async for item in source.discover(since):
        run.discovered += 1

        existing = repo.get_document_by_url_hash(session, item.url_hash)
        etag = existing.etag if existing else None
        last_modified = existing.last_modified if existing else None

        try:
            raw = await fetcher.fetch(item, etag=etag, last_modified=last_modified)
        except FetchError as exc:
            run.failed += 1
            consecutive_failures += 1
            repo.record_fetch_error(
                session, source.name, item.url, type(exc).__name__, str(exc)
            )
            if consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                status = "circuit_open"
                repo.finish_run(
                    session,
                    run,
                    status,
                    note=f"{consecutive_failures} consecutive failures; source quarantined",
                )
                session.flush()
                return run
            continue

        consecutive_failures = 0

        if raw is None:  # 304 Not Modified
            continue

        if existing is not None and existing.content_hash == raw.content_hash:
            continue

        run.fetched += 1
        raw_path = archive.store(raw)

        for parsed in source.parse(raw):
            repo.upsert_document(session, parsed, raw, raw_path)
            for fact in parsed.vulnerabilities:
                repo.upsert_vulnerability(session, fact)
            for warning in parsed.warnings:
                logger.warning("parse warning [%s] %s: %s", source.name, parsed.url, warning)
            run.parsed += 1

        processed_since_commit += 1
        if processed_since_commit >= COMMIT_EVERY:
            session.flush()
            processed_since_commit = 0

    repo.finish_run(session, run, status)
    if status == "ok":
        repo.mark_source_success(session, source.name, run.finished_at)
    session.flush()
    return run
```

Note the ordering: `session.flush()` rather than `session.commit()`, so the caller controls transaction boundaries and tests can roll back.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_pipeline.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add src/crawler/core/pipeline.py tests/core/test_pipeline.py
git commit -m "feat: pipeline with dedup, conditional fetch, and circuit breaker"
```

---

### Task 9: CISA KEV source adapter

**Files:**
- Create: `src/crawler/sources/kev.py`
- Create: `tests/fixtures/kev/catalog.json`
- Test: `tests/sources/test_kev.py`

**Interfaces:**
- Consumes: `DiscoveredItem`, `ParsedDoc`, `RawDocument`, `VulnerabilityFact`, `RateLimit`, `register`
- Produces: `crawler.sources.kev.KevSource` — registered under the name `"kev"`

**Source details:** The catalog is a single JSON file at
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
Its shape is `{"title", "catalogVersion", "dateReleased", "count", "vulnerabilities": [...]}`,
where each entry has `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`,
`shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`.

`discover` yields exactly one item (the catalog URL). `parse` returns one `ParsedDoc` per
vulnerability, each with a synthetic fragment URL so every entry gets its own `url_hash`.

- [ ] **Step 1: Create the test fixture**

Create `tests/fixtures/kev/catalog.json`:

```json
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.03.15",
  "dateReleased": "2026-03-15T12:00:00.0000Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-21412",
      "vendorProject": "Microsoft",
      "product": "Windows SmartScreen",
      "vulnerabilityName": "Microsoft Windows SmartScreen Security Feature Bypass Vulnerability",
      "dateAdded": "2024-02-13",
      "shortDescription": "Microsoft Windows SmartScreen contains a security feature bypass vulnerability that allows an attacker to bypass SmartScreen protections.",
      "requiredAction": "Apply mitigations per vendor instructions or discontinue use.",
      "dueDate": "2024-03-05",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412"
    },
    {
      "cveID": "CVE-2023-4966",
      "vendorProject": "Citrix",
      "product": "NetScaler ADC and NetScaler Gateway",
      "vulnerabilityName": "Citrix NetScaler Sensitive Information Disclosure Vulnerability",
      "dateAdded": "2023-10-18",
      "shortDescription": "Citrix NetScaler contains a buffer overflow vulnerability leading to sensitive information disclosure.",
      "requiredAction": "Apply mitigations per vendor instructions.",
      "dueDate": "2023-11-08",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

Create `tests/sources/test_kev.py`:

```python
import json
from datetime import datetime, timezone
from pathlib import Path

from crawler.core.models import DiscoveredItem, RawDocument
from crawler.sources.kev import KevSource

FIXTURE = Path(__file__).parent.parent / "fixtures" / "kev" / "catalog.json"


def make_raw() -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(url=KevSource.CATALOG_URL, source="kev"),
        content=FIXTURE.read_bytes(),
        content_type="application/json",
        http_status=200,
        fetched_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )


async def test_discover_yields_the_catalog_url():
    items = [item async for item in KevSource().discover(since=datetime(2020, 1, 1, tzinfo=timezone.utc))]

    assert len(items) == 1
    assert items[0].url == KevSource.CATALOG_URL


def test_parse_returns_one_doc_per_vulnerability():
    docs = KevSource().parse(make_raw())

    assert len(docs) == 2
    assert {d.title for d in docs} == {
        "Microsoft Windows SmartScreen Security Feature Bypass Vulnerability",
        "Citrix NetScaler Sensitive Information Disclosure Vulnerability",
    }


def test_each_doc_gets_a_unique_url():
    docs = KevSource().parse(make_raw())

    assert docs[0].url.endswith("#CVE-2024-21412")
    assert len({d.url_hash for d in docs}) == 2


def test_parse_emits_vulnerability_facts_with_kev_flags():
    docs = KevSource().parse(make_raw())
    fact = docs[0].vulnerabilities[0]

    assert fact.cve_id == "CVE-2024-21412"
    assert fact.vendor == "Microsoft"
    assert fact.product == "Windows SmartScreen"
    assert fact.kev_listed is True
    assert fact.kev_added_date == datetime(2024, 2, 13, tzinfo=timezone.utc)


def test_body_text_includes_description_and_required_action():
    docs = KevSource().parse(make_raw())

    assert "bypass SmartScreen protections" in docs[0].body_text
    assert "Apply mitigations" in docs[0].body_text


def test_malformed_entry_is_skipped_with_a_warning():
    payload = json.loads(FIXTURE.read_text())
    payload["vulnerabilities"].append({"vendorProject": "NoCve"})  # missing cveID
    raw = RawDocument(
        item=DiscoveredItem(url=KevSource.CATALOG_URL, source="kev"),
        content=json.dumps(payload).encode(),
        content_type="application/json",
        http_status=200,
        fetched_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )

    docs = KevSource().parse(raw)

    assert len(docs) == 2  # the malformed entry produced no document
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/sources/test_kev.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'crawler.sources.kev'`

- [ ] **Step 4: Implement `src/crawler/sources/kev.py`**

```python
import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from crawler.core.models import DiscoveredItem, ParsedDoc, RawDocument, VulnerabilityFact
from crawler.sources.base import RateLimit, register

logger = logging.getLogger(__name__)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class KevSource:
    """CISA Known Exploited Vulnerabilities catalog: one JSON file, many vulnerabilities."""

    CATALOG_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    name = "kev"
    kind = "api"
    license = "public-domain"
    rate_limit = RateLimit(requests=1, per_seconds=2.0)

    async def discover(self, since: datetime) -> AsyncIterator[DiscoveredItem]:
        yield DiscoveredItem(url=self.CATALOG_URL, source=self.name)

    def parse(self, raw: RawDocument) -> list[ParsedDoc]:
        payload = json.loads(raw.content)
        docs: list[ParsedDoc] = []

        for entry in payload.get("vulnerabilities", []):
            cve_id = entry.get("cveID")
            if not cve_id:
                logger.warning("kev: entry without cveID skipped: %r", entry.get("product"))
                continue

            added = _parse_date(entry.get("dateAdded"))
            body = "\n\n".join(
                part
                for part in (
                    entry.get("shortDescription"),
                    entry.get("requiredAction"),
                    f"Known ransomware campaign use: {entry.get('knownRansomwareCampaignUse')}"
                    if entry.get("knownRansomwareCampaignUse")
                    else None,
                )
                if part
            )

            docs.append(
                ParsedDoc(
                    url=f"{self.CATALOG_URL}#{cve_id}",
                    source=self.name,
                    title=entry.get("vulnerabilityName") or cve_id,
                    body_text=body,
                    license=self.license,
                    published_at=added,
                    vulnerabilities=(
                        VulnerabilityFact(
                            cve_id=cve_id,
                            vendor=entry.get("vendorProject"),
                            product=entry.get("product"),
                            description=entry.get("shortDescription"),
                            kev_listed=True,
                            kev_added_date=added,
                        ),
                    ),
                )
            )

        return docs


register(KevSource())
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/sources/test_kev.py -v`
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add src/crawler/sources/kev.py tests/sources/test_kev.py tests/fixtures
git commit -m "feat: CISA KEV source adapter"
```

---

### Task 10: Wire the CLI and verify end-to-end

**Files:**
- Modify: `src/crawler/cli.py`
- Modify: `src/crawler/sources/__init__.py`
- Create: `tests/test_end_to_end.py`
- Create: `README.md`

**Interfaces:**
- Consumes: everything from Tasks 1–9
- Produces:
  - `crawler.cli` commands: `crawl [--source X] [--since DATE]`, `sources list`, `stats`
  - `crawler.cli.build_fetcher() -> Fetcher`

- [ ] **Step 1: Make source registration automatic**

Edit `src/crawler/sources/__init__.py` so importing the package registers every adapter:

```python
from crawler.sources import kev  # noqa: F401  - imported for its registration side effect
```

- [ ] **Step 2: Write the failing end-to-end test**

Create `tests/test_end_to_end.py`:

```python
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import select

from crawler.core.archive import RawArchive
from crawler.core.fetch import Fetcher
from crawler.core.pipeline import run_source
from crawler.core.ratelimit import DomainRateLimiter
from crawler.db.schema import Document, Vulnerability
from crawler.sources.base import RateLimit
from crawler.sources.kev import KevSource

FIXTURE = Path(__file__).parent / "fixtures" / "kev" / "catalog.json"


async def test_kev_flows_from_http_to_database(db_session, tmp_path):
    def handler(request):
        assert request.url.path.endswith("known_exploited_vulnerabilities.json")
        return httpx.Response(
            200, content=FIXTURE.read_bytes(), headers={"content-type": "application/json"}
        )

    async def no_sleep(seconds):
        return None

    fetcher = Fetcher(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limiter=DomainRateLimiter(RateLimit(requests=10, per_seconds=1.0), sleep=no_sleep),
        user_agent="test-agent",
        sleep=no_sleep,
    )

    run = await run_source(
        KevSource(),
        fetcher,
        RawArchive(tmp_path),
        db_session,
        since=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )

    assert run.status == "ok"
    assert run.parsed == 2

    docs = db_session.execute(select(Document).where(Document.source == "kev")).scalars().all()
    assert len(docs) == 2
    assert all(d.raw_path.startswith("kev/") for d in docs)
    assert all(d.body_text for d in docs)

    kev_vuln = db_session.get(Vulnerability, "CVE-2024-21412")
    assert kev_vuln.kev_listed is True
    assert kev_vuln.vendor == "Microsoft"


async def test_rerunning_is_idempotent(db_session, tmp_path):
    def handler(request):
        return httpx.Response(
            200, content=FIXTURE.read_bytes(), headers={"content-type": "application/json"}
        )

    async def no_sleep(seconds):
        return None

    def build():
        return Fetcher(
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            limiter=DomainRateLimiter(RateLimit(requests=10, per_seconds=1.0), sleep=no_sleep),
            user_agent="test-agent",
            sleep=no_sleep,
        )

    since = datetime(2020, 1, 1, tzinfo=timezone.utc)
    await run_source(KevSource(), build(), RawArchive(tmp_path), db_session, since=since)
    db_session.flush()
    second = await run_source(KevSource(), build(), RawArchive(tmp_path), db_session, since=since)

    # Content is byte-identical, so the second run stores nothing new.
    assert second.parsed == 0
    docs = db_session.execute(select(Document).where(Document.source == "kev")).scalars().all()
    assert len(docs) == 2
```

- [ ] **Step 3: Run the end-to-end tests**

Run: `uv run pytest tests/test_end_to_end.py -v`
Expected: 2 passed.

Unlike every other test in this plan, this one is **not** expected to fail first. It is an
integration test over components Tasks 1–9 already built, so there is no red step to write.
If it fails, the failure tells you which task's contract was implemented incorrectly — fix
that task's source file, not this test.

- [ ] **Step 4: Add the `crawl`, `sources list`, and `stats` commands**

Add to `src/crawler/cli.py`:

```python
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select

from crawler.core.archive import RawArchive
from crawler.core.fetch import Fetcher, RobotsCache
from crawler.core.pipeline import run_source
from crawler.core.ratelimit import DomainRateLimiter
from crawler.db.schema import Document
from crawler.db.session import session_scope
from crawler.sources import base as source_registry

sources_app = typer.Typer(help="Source registry.")
app.add_typer(sources_app, name="sources")


def build_fetcher() -> Fetcher:
    settings = get_settings()
    client = httpx.AsyncClient(timeout=settings.request_timeout)
    limiter = DomainRateLimiter(default=source_registry.RateLimit(requests=1, per_seconds=2.0))
    robots = RobotsCache(client=client, user_agent=settings.user_agent)
    return Fetcher(
        client=client, limiter=limiter, user_agent=settings.user_agent, robots=robots
    )


@sources_app.command("list")
def sources_list() -> None:
    """Show every registered source."""
    import crawler.sources  # noqa: F401 - triggers registration

    for source in source_registry.all_sources():
        typer.echo(f"{source.name:<16} {source.kind:<6} {source.license}")


@app.command()
def crawl(
    source: str | None = typer.Option(None, help="Only crawl this source."),
    since_days: int = typer.Option(30, help="Look back this many days."),
) -> None:
    """Fetch new documents from every enabled source."""
    import crawler.sources  # noqa: F401 - triggers registration

    settings = get_settings()
    since = datetime.now(timezone.utc) - timedelta(days=since_days)
    targets = (
        [source_registry.get_source(source)] if source else source_registry.all_sources()
    )

    async def _run() -> None:
        fetcher = build_fetcher()
        archive = RawArchive(settings.raw_archive_dir)
        for target in targets:
            with session_scope() as session:
                run = await run_source(target, fetcher, archive, session, since)
                typer.echo(
                    f"{target.name}: discovered={run.discovered} fetched={run.fetched} "
                    f"parsed={run.parsed} failed={run.failed} status={run.status}"
                )

    asyncio.run(_run())


@app.command()
def stats() -> None:
    """Summarize what is in the database."""
    with session_scope() as session:
        rows = session.execute(
            select(Document.source, func.count(Document.id)).group_by(Document.source)
        ).all()
    if not rows:
        typer.echo("No documents yet. Run: crawler crawl")
        return
    for name, count in rows:
        typer.echo(f"{name:<16} {count:>8} documents")
```

- [ ] **Step 5: Run the real crawl against CISA**

```powershell
uv run crawler sources list
uv run crawler crawl --source kev
uv run crawler stats
```

Expected: `sources list` shows `kev api public-domain`; `crawl` reports roughly
`discovered=1 fetched=1 parsed=1200 failed=0 status=ok`; `stats` shows a matching document count.

This is the first and only step in this plan that touches the live internet.

- [ ] **Step 6: Verify the raw archive was written**

Run: `Get-ChildItem -Recurse data\raw`
Expected: one `.json.gz` file under `data\raw\kev\<year>\<month>\`.

- [ ] **Step 7: Write `README.md`**

```markdown
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
```

- [ ] **Step 8: Run the full test suite and linter**

```powershell
uv run ruff check src tests
uv run pytest -v
```

Expected: ruff clean, all tests pass.

- [ ] **Step 9: Commit**

```bash
git add src/crawler/cli.py src/crawler/sources/__init__.py tests/test_end_to_end.py README.md
git commit -m "feat: crawl/sources/stats commands and end-to-end KEV ingestion"
```

---

## Definition of Done

- `uv run crawler db ping` reports the Postgres version from the WSL container.
- `uv run crawler crawl --source kev` ingests the live KEV catalog.
- `uv run crawler stats` shows the resulting document count.
- `robots.txt` is fetched once per host and honoured before any page request.
- Re-running `crawl` adds no duplicate documents.
- `uv run pytest` passes with no network access.
- `uv run ruff check src tests` is clean.

## What Plan 2 will add

NVD (paginated API, strict rate limits), MITRE ATT&CK (STIX bundle populating `actors` and
`techniques`), news RSS (config-driven, `trafilatura` body extraction), CISA advisories,
vendor PDF reports, abuse.ch, plus the full rule-based extraction layer: refanging, CVE and
IOC regexes with false-positive controls, and attack-type and sector scoring.

## What Plan 3 will add

LLM enrichment (`enrich`), `reparse` over the raw archive, `export` to JSONL and Parquet,
and the `doctor` drift-detection command.

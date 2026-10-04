# CTI Crawler & Extractor Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the crawler's source list into `config/sources.yaml`, fold the text-extractor's rules + LLM pipeline into the crawler as a headless `crawler extract` command, and make a strict `config/ontology.json` the only source of entity and relation types. The LLM is held to that ontology at the API level with structured outputs.

**Architecture:** `crawler.sources.catalog` parses and validates `sources.yaml` with pydantic. Then `crawler.sources.loader` builds and registers adapters from it and installs each source's rate limit on the shared `DomainRateLimiter`. The new package `crawler.extraction` holds code ported from `text-extractor`: tokenizer, regex patterns, the ATT&CK dictionary matcher, span placement and the validator. All of it is rewired to an `Ontology` loaded from `config/ontology.json`. One async OpenAI-compatible client serves Mistral, Gemini (via its OpenAI endpoint) and Grok. It sends a strict JSON Schema generated from the ontology. It runs through the crawler's own `DomainRateLimiter` plus a semaphore. `crawler extract` takes documents from Postgres that have no output file yet, runs rules then the LLM per sentence, validates the result, and writes `data/extracted/<url_hash>.json` atomically.

**Tech Stack:** Python 3.12, uv, Typer, SQLAlchemy 2, pydantic / pydantic-settings, httpx (async), PyYAML (new), pytest + pytest-asyncio (`asyncio_mode = "auto"`), ruff.

**Spec:** `C:\Project\kunjadi-project\CTI_INTEGRATION.md` (Task 1 copies it to `docs/superpowers/specs/2026-10-04-cti-integration.md` so it travels with the repo).

**Repos:** All work happens in the git repo `C:\Project\kunjadi-project\Crawler`, run from that directory. The extractor is read-only source material at `C:\Project\kunjadi-project\text-extractor` (`../text-extractor` from the crawler). The spec's "Extractor-main" is this folder. Its web app (`app.py`, `static/`) is not ported. Nothing in `text-extractor` is modified.

**Baseline:** On a machine without Postgres, `uv run pytest` gives 32 passed and 14 errors. The errors are DB tests failing with `OperationalError` because no database is reachable. With `docker compose up -d` (WSL) they pass. Every "run the suite" step below expects **no new failures** beyond those DB errors when Postgres is down.

## Global Constraints

- Do not modify the database schema; no Alembic migration. Extraction output goes to JSON files only.
- Keep the crawler's existing `Fetcher` and concurrency controls (`DomainRateLimiter`, `MAX_CONCURRENT_SOURCES`); LLM traffic also goes through a `DomainRateLimiter` and a semaphore.
- Production-ready code with type hints on every new or ported function.
- Order: generate `config/sources.yaml` and `config/ontology.json` first, then refactor code to consume them.
- `config/ontology.json` defines exactly 15 entity types: Threat actor, Threat group, Malware, Attack technique, Vulnerability, Software, Tool, Organization, Attack pattern, File/hash, Network infrastructure, Asset/system, Security team, Time, Location.
- Relations are exactly the spec's table (Objective 2). Where the spec writes `A/B`, every combination is allowed. The spec spelling `sub_technique_of` is kept verbatim.
- The extractor must never output an entity type or relation triple outside the ontology. The provider enforces this through a strict JSON Schema, and a validator re-checks every reply.
- Output path: `data/extracted/<url_hash>.json`, one file per document. A file's presence means "extracted".
- Ruff: line length 100; keep `datetime.now(timezone.utc)` spelling (UP017 is ignored on purpose). `ruff check src tests` must pass after every task.
- Run `ruff format` only on files the task creates; the lint steps do this by formatting untracked `.py` files before `git add`. Five existing files are not ruff-formatted: `cli.py`, `core/fetch.py`, `core/pipeline.py`, `sources/sitemap.py`, `tests/core/test_fetch.py`. Reformatting them would bury the real diff, so never run `ruff format` over all of `src`/`tests`.
- Test file basenames must be unique across `tests/`. There are no `__init__.py` files, so a duplicate basename breaks collection. `tests/core/test_pipeline.py` already exists, so the new pipeline test is `test_extract_pipeline.py`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Interrupted run (Ctrl-C, crash) during a write.** It must not leave a partial `<url_hash>.json` that counts as done. Writes go to a temp file and are moved into place with `os.replace`. Test: Task 9 `test_failed_write_leaves_no_file`.
2. **LLM provider down, out of quota, or rejecting the key or schema.** Documents must not be marked extracted with rules-only output. The run must also not burn through the whole backlog. A document with any LLM-failed sentence is not written, so it is retried next run. Three consecutive documents with every sentence failed abort the run. A missing API key fails before touching the DB. Tests: Task 9 `test_documents_with_llm_failures_are_not_written`, `test_three_dead_documents_in_a_row_abort`; Task 10 `test_missing_api_key_fails_before_the_database`.
3. **Real article text: curly quotes, possessives, tabs, CRLF, runs of spaces, leading whitespace.** Character offsets must slice the original `body_text` exactly. Test: Task 8 `test_offsets_survive_quotes_possessives_and_whitespace`.
4. **LLM reply naming an entity string it never declared, or claiming the wrong type for an entity.** The relation must be dropped, not trusted. Tests: Task 6 `test_parse_drops_relation_whose_end_is_not_an_entity`, `test_parse_drops_relation_with_wrong_claimed_type`.
5. **Typo in `sources.yaml`** (unknown key, missing `child_pattern`, duplicate name, bad URL). It must fail at startup with the file and field named, not halfway through a crawl. Two sources on one host must get the slower limit. Tests: Task 1 `test_invalid_catalogs_fail_loudly`; Task 2 `test_shared_host_gets_the_slower_limit`.

---

### Task 1: `config/sources.yaml` and its validated loader

**Files:**
- Create: `config/sources.yaml`
- Create: `src/crawler/sources/catalog.py`
- Create: `tests/sources/test_catalog.py`
- Create: `docs/superpowers/specs/2026-10-04-cti-integration.md` (copy of the spec)
- Modify: `src/crawler/config.py` (add `sources_config`)
- Modify: `pyproject.toml` / `uv.lock` (add `pyyaml`)

**Interfaces:**
- Consumes: `crawler.core.models.RateLimit(requests: int, per_seconds: float)`
- Produces:
  - `class CatalogError(ValueError)`
  - `class RateLimitConfig(BaseModel)`: `requests: int`, `per_seconds: float`, `.to_rate_limit() -> RateLimit`
  - `RssConfig`, `SitemapConfig` (+ `child_pattern: str`, `article_pattern: str = ""`), `WordPressConfig`, `KevConfig`, `NvdConfig`, each with `name`, `adapter`, `entry_url`, `rate_limit: RateLimitConfig`, `license: str`, `enabled: bool`
  - `SourceConfig` = discriminated union of the five on `adapter`
  - `load_catalog(path: Path) -> list[SourceConfig]` (file order, disabled included)
  - `Settings.sources_config: Path = Path("config/sources.yaml")`

- [ ] **Step 1: Branch, add the dependency, copy the spec**

```bash
git checkout -b feature/cti-extraction
uv add pyyaml
mkdir -p docs/superpowers/specs
cp ../CTI_INTEGRATION.md docs/superpowers/specs/2026-10-04-cti-integration.md
```

- [ ] **Step 2: Write `config/sources.yaml`**

It carries the 13 sources currently hardcoded in `news_rss.py`, `sitemap.py`, `wordpress.py`, `kev.py` and `nvd.py`. URLs, patterns and rate limits are unchanged. The explanatory comments move here from the Python modules.

```yaml
# Every source the crawler knows about. `uv run crawler sources list` shows what loaded.
#
# Fields (all adapters)
#   name        unique id, lowercase; stored as documents.source
#   adapter     rss | sitemap | wordpress | kev | nvd
#   entry_url   where discovery starts: feed, sitemap index, WordPress posts API, or catalog
#   rate_limit  {requests, per_seconds}, enforced per host. Default 1 per 2.0s.
#   license     stored on every document from this source. Default copyrighted
#               (public-domain for kev and nvd).
#   enabled     false keeps an entry on file without crawling it. Default true.
#
# Adapter-specific
#   sitemap     child_pattern    (required) substring identifying child sitemaps holding articles
#               article_pattern  (optional) substring every article URL must contain
#
# Removed rather than worked around:
#   darkreading  - returns 403 on every article; the publisher refuses automated clients,
#                  and spoofing a browser User-Agent to get past that is not acceptable.
#   googletag    - https://blog.google/threat-analysis-group/rss/ now 404s.

sources:
  # --- RSS: only the sites with no better route. A feed carries a few weeks at most.
  # bleepingcomputer publishes gzipped .txt.gz sitemaps mixed with forum threads, and
  # securityweek returns 403 on both its sitemap and its WordPress API, so both stay on RSS.
  # Slower than the default: small publishers, and every article in a feed is fetched back to back.
  - name: bleepingcomputer
    adapter: rss
    entry_url: https://www.bleepingcomputer.com/feed/
    rate_limit: {requests: 1, per_seconds: 3.0}
    license: copyrighted

  - name: securityweek
    adapter: rss
    entry_url: https://www.securityweek.com/feed/
    rate_limit: {requests: 1, per_seconds: 3.0}
    license: copyrighted

  - name: projectzero
    adapter: rss
    entry_url: https://googleprojectzero.blogspot.com/feeds/posts/default
    rate_limit: {requests: 1, per_seconds: 3.0}
    license: copyrighted

  # --- Sitemaps: whole archive, one request per article.
  - name: krebsonsecurity
    adapter: sitemap
    entry_url: https://krebsonsecurity.com/sitemap.xml
    child_pattern: posts-post
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  - name: thehackernews
    adapter: sitemap
    entry_url: https://thehackernews.com/sitemap.xml
    child_pattern: "sitemap.xml?page="
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  - name: therecord
    adapter: sitemap
    entry_url: https://therecord.media/sitemap.xml
    child_pattern: sitemaps/page-
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  - name: talos
    adapter: sitemap
    entry_url: https://blog.talosintelligence.com/sitemap.xml
    child_pattern: sitemap-posts
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  - name: sentinelone
    adapter: sitemap
    entry_url: https://www.sentinelone.com/sitemap.xml
    child_pattern: post-sitemap
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  # --- WordPress REST API: 100 full-text posts per request; always the polite option.
  - name: unit42
    adapter: wordpress
    entry_url: https://unit42.paloaltonetworks.com/wp-json/wp/v2/posts
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  - name: microsoft
    adapter: wordpress
    entry_url: https://www.microsoft.com/en-us/security/blog/wp-json/wp/v2/posts
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  # Root path, not /blog: the API lives at the domain root even though every article sits
  # under /blog/. Its post sitemap times out server-side even at 60s; this answers in 0.5s.
  - name: malwarebytes
    adapter: wordpress
    entry_url: https://www.malwarebytes.com/wp-json/wp/v2/posts
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: copyrighted

  # --- Structured feeds.
  - name: kev
    adapter: kev
    entry_url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    rate_limit: {requests: 1, per_seconds: 2.0}
    license: public-domain

  # Without an API key NVD allows 5 requests per 30 seconds; 6.5s keeps us comfortably legal.
  - name: nvd
    adapter: nvd
    entry_url: https://services.nvd.nist.gov/rest/json/cves/2.0
    rate_limit: {requests: 1, per_seconds: 6.5}
    license: public-domain
```

- [ ] **Step 3: Write the failing tests** — `tests/sources/test_catalog.py`

```python
from pathlib import Path

import pytest
import yaml

from crawler.core.models import RateLimit
from crawler.sources.catalog import (
    CatalogError,
    KevConfig,
    NvdConfig,
    RssConfig,
    SitemapConfig,
    WordPressConfig,
    load_catalog,
)

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "sources.yaml"

EXPECTED = {
    "bleepingcomputer": RssConfig,
    "securityweek": RssConfig,
    "projectzero": RssConfig,
    "krebsonsecurity": SitemapConfig,
    "thehackernews": SitemapConfig,
    "therecord": SitemapConfig,
    "talos": SitemapConfig,
    "sentinelone": SitemapConfig,
    "unit42": WordPressConfig,
    "microsoft": WordPressConfig,
    "malwarebytes": WordPressConfig,
    "kev": KevConfig,
    "nvd": NvdConfig,
}

RSS = {"name": "s", "adapter": "rss", "entry_url": "https://e.org/feed"}


def catalog(*entries: dict) -> str:
    return yaml.safe_dump({"sources": list(entries)})


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "sources.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_shipped_catalog_lists_every_source_with_its_adapter():
    assert {s.name: type(s) for s in load_catalog(SHIPPED)} == EXPECTED


def test_shipped_catalog_preserves_the_hardcoded_settings():
    by_name = {s.name: s for s in load_catalog(SHIPPED)}

    assert by_name["bleepingcomputer"].rate_limit.to_rate_limit() == RateLimit(1, 3.0)
    assert by_name["nvd"].rate_limit.to_rate_limit() == RateLimit(1, 6.5)
    assert by_name["kev"].license == "public-domain"
    assert by_name["krebsonsecurity"].child_pattern == "posts-post"
    assert by_name["thehackernews"].child_pattern == "sitemap.xml?page="
    assert by_name["malwarebytes"].entry_url == "https://www.malwarebytes.com/wp-json/wp/v2/posts"
    assert all(s.enabled for s in by_name.values())


def test_adapter_specific_flags_and_defaults(tmp_path):
    entry = {
        "name": "site",
        "adapter": "sitemap",
        "entry_url": "https://example.org/sitemap.xml",
        "child_pattern": "post-sitemap",
        "article_pattern": "/blog/",
    }
    [site] = load_catalog(write(tmp_path, catalog(entry)))

    assert isinstance(site, SitemapConfig)
    assert (site.child_pattern, site.article_pattern) == ("post-sitemap", "/blog/")
    assert site.enabled is True
    assert site.license == "copyrighted"
    assert site.rate_limit.to_rate_limit() == RateLimit(1, 2.0)


def test_kev_and_nvd_default_to_public_domain(tmp_path):
    path = write(
        tmp_path,
        catalog(
            {"name": "k", "adapter": "kev", "entry_url": "https://e.org/kev.json"},
            {"name": "n", "adapter": "nvd", "entry_url": "https://e.org/nvd"},
        ),
    )
    assert [s.license for s in load_catalog(path)] == ["public-domain", "public-domain"]


@pytest.mark.parametrize(
    "body, message",
    [
        (catalog({**RSS, "adapter": "sitemap"}), "child_pattern"),
        (catalog({**RSS, "adapter": "gopher"}), "adapter"),
        (catalog({**RSS, "child_patern": "x"}), "child_patern"),
        (catalog({**RSS, "entry_url": "ftp://e.org/"}), "entry_url"),
        (catalog({**RSS, "name": "Has Spaces"}), "name"),
        (catalog({**RSS, "rate_limit": {"requests": 0, "per_seconds": 1}}), "requests"),
        (catalog(RSS, {**RSS, "entry_url": "https://e.org/other"}), "duplicate source name 's'"),
        ("", "dictionary"),
        ("sources: [\n", "not valid YAML"),
    ],
)
def test_invalid_catalogs_fail_loudly(tmp_path, body, message):
    with pytest.raises(CatalogError, match=message):
        load_catalog(write(tmp_path, body))


def test_missing_file_names_the_path(tmp_path):
    with pytest.raises(CatalogError, match="not found"):
        load_catalog(tmp_path / "nope.yaml")
```

- [ ] **Step 4: Run to verify failure**

Run: `uv run pytest tests/sources/test_catalog.py -v`
Expected: collection error, `ModuleNotFoundError: No module named 'crawler.sources.catalog'`

- [ ] **Step 5: Implement** — `src/crawler/sources/catalog.py`

```python
"""Typed view of config/sources.yaml.

Each entry names an adapter, and the adapter's own flags are checked against that adapter's
model. A typo in the file therefore fails when the crawler starts, not halfway through a crawl.
"""

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from crawler.core.models import RateLimit


class CatalogError(ValueError):
    """config/sources.yaml is missing, malformed, or describes an invalid source."""


class RateLimitConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requests: int = Field(ge=1)
    per_seconds: float = Field(gt=0)

    def to_rate_limit(self) -> RateLimit:
        return RateLimit(requests=self.requests, per_seconds=self.per_seconds)


class _SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    entry_url: str = Field(pattern=r"^https?://\S+$")
    rate_limit: RateLimitConfig = RateLimitConfig(requests=1, per_seconds=2.0)
    license: str = Field(default="copyrighted", min_length=1, max_length=32)
    enabled: bool = True


class RssConfig(_SourceConfig):
    adapter: Literal["rss"]


class SitemapConfig(_SourceConfig):
    adapter: Literal["sitemap"]
    child_pattern: str = Field(min_length=1)
    article_pattern: str = ""


class WordPressConfig(_SourceConfig):
    adapter: Literal["wordpress"]


class KevConfig(_SourceConfig):
    adapter: Literal["kev"]
    license: str = Field(default="public-domain", min_length=1, max_length=32)


class NvdConfig(_SourceConfig):
    adapter: Literal["nvd"]
    license: str = Field(default="public-domain", min_length=1, max_length=32)


SourceConfig = Annotated[
    RssConfig | SitemapConfig | WordPressConfig | KevConfig | NvdConfig,
    Field(discriminator="adapter"),
]


class _CatalogFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[SourceConfig]

    @model_validator(mode="after")
    def _unique_names(self) -> "_CatalogFile":
        seen: set[str] = set()
        for source in self.sources:
            if source.name in seen:
                raise ValueError(f"duplicate source name {source.name!r}")
            seen.add(source.name)
        return self


def load_catalog(path: Path) -> list[SourceConfig]:
    """Every source in `path`, in file order, disabled ones included."""
    path = Path(path)
    try:
        # utf-8-sig: PowerShell 5.1 saves UTF-8 with a byte-order mark.
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise CatalogError(f"{path}: file not found") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"{path}: not valid YAML ({exc})") from exc

    try:
        return _CatalogFile.model_validate(data).sources
    except ValidationError as exc:
        raise CatalogError(f"{path}: {exc}") from exc
```

In `src/crawler/config.py`, add to `Settings` after `raw_archive_dir`:

```python
    sources_config: Path = Path("config/sources.yaml")
```

- [ ] **Step 6: Run to verify pass**

Run: `uv run pytest tests/sources/test_catalog.py -v`
Expected: all PASS

- [ ] **Step 7: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add config/sources.yaml src/crawler/sources/catalog.py src/crawler/config.py tests/sources/test_catalog.py pyproject.toml uv.lock docs/superpowers/specs/2026-10-04-cti-integration.md docs/superpowers/plans/2026-10-04-cti-extraction-integration.md
git commit -m "feat: config/sources.yaml with a validated catalog loader

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Build and register adapters from the catalog

**Files:**
- Create: `src/crawler/sources/loader.py`
- Create: `tests/sources/test_loader.py`
- Modify: `src/crawler/sources/base.py` (Protocol gains `entry_url`)
- Modify: `src/crawler/sources/__init__.py` (no more import side effects)
- Modify: `src/crawler/sources/news_rss.py`, `sitemap.py`, `wordpress.py`, `kev.py`, `nvd.py` (constructor takes settings; `SITES` lists and `register(...)` calls removed)
- Modify: `src/crawler/cli.py` (load catalog, apply limits)

**Interfaces:**
- Consumes: `load_catalog`, `CatalogError`, config classes (Task 1); `DomainRateLimiter.set_limit(host, RateLimit)`; `base.register`, `base.all_sources`
- Produces:
  - `build_source(config: SourceConfig) -> Source`
  - `register_from_config(path: Path) -> list[Source]` (enabled only, file order)
  - `apply_rate_limits(limiter: DomainRateLimiter, sources: Iterable[Source]) -> None`
  - Every adapter instance has `name`, `entry_url`, `rate_limit`, `license` attributes
  - Constructors: `NewsRssSource(name, feed_url, rate_limit=..., license="copyrighted")`, `SitemapSource(site, rate_limit=..., license="copyrighted")`, `WordPressSource(name, api, rate_limit=..., license="copyrighted")`, `KevSource(name="kev", catalog_url=KevSource.CATALOG_URL, rate_limit=..., license="public-domain")`, `NvdSource(name="nvd", api=API, rate_limit=NO_KEY_LIMIT, license="public-domain")`

**Behaviour change, intended:** until now only NVD installed its own limit. Every other `rate_limit` was declared but never applied, so all hosts ran at the 1-per-2s default. `apply_rate_limits` makes the YAML's limits real. RSS hosts now run at the 1-per-3s their code always claimed.

**Do not change default URLs.** `KevSource` keys documents by `f"{catalog_url}#{cve_id}"`. A different URL would change every KEV `url_hash` and duplicate the KEV corpus.

- [ ] **Step 1: Write the failing tests** — `tests/sources/test_loader.py`

```python
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from crawler.core.models import DiscoveredItem, RateLimit, RawDocument
from crawler.sources import base
from crawler.sources.catalog import (
    KevConfig,
    NvdConfig,
    RateLimitConfig,
    RssConfig,
    SitemapConfig,
    WordPressConfig,
)
from crawler.sources.kev import KevSource
from crawler.sources.loader import apply_rate_limits, build_source, register_from_config
from crawler.sources.news_rss import NewsRssSource
from crawler.sources.nvd import NvdSource
from crawler.sources.sitemap import SitemapSource
from crawler.sources.wordpress import WordPressSource

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "sources.yaml"
SLOW = RateLimitConfig(requests=1, per_seconds=5.0)


@pytest.fixture(autouse=True)
def empty_registry(monkeypatch):
    monkeypatch.setattr(base, "_REGISTRY", {})


class RecordingLimiter:
    def __init__(self) -> None:
        self.limits: dict[str, RateLimit] = {}

    def set_limit(self, host: str, limit: RateLimit) -> None:
        self.limits[host] = limit


@pytest.mark.parametrize(
    "config, cls",
    [
        (
            RssConfig(name="a", adapter="rss", entry_url="https://a.example/feed", rate_limit=SLOW),
            NewsRssSource,
        ),
        (
            SitemapConfig(
                name="b",
                adapter="sitemap",
                entry_url="https://b.example/sitemap.xml",
                child_pattern="posts",
                rate_limit=SLOW,
            ),
            SitemapSource,
        ),
        (
            WordPressConfig(
                name="c", adapter="wordpress", entry_url="https://c.example/wp", rate_limit=SLOW
            ),
            WordPressSource,
        ),
        (
            KevConfig(name="d", adapter="kev", entry_url="https://d.example/k.json", rate_limit=SLOW),
            KevSource,
        ),
        (
            NvdConfig(name="e", adapter="nvd", entry_url="https://e.example/nvd", rate_limit=SLOW),
            NvdSource,
        ),
    ],
)
def test_build_source_carries_catalog_settings(config, cls):
    source = build_source(config)

    assert isinstance(source, cls)
    assert source.name == config.name
    assert source.entry_url == config.entry_url
    assert source.rate_limit == RateLimit(requests=1, per_seconds=5.0)
    assert source.license == config.license


def test_sitemap_patterns_reach_the_adapter():
    source = build_source(
        SitemapConfig(
            name="b",
            adapter="sitemap",
            entry_url="https://b.example/sitemap.xml",
            child_pattern="posts",
            article_pattern="/blog/",
        )
    )
    assert (source._site.index, source._site.child, source._site.article) == (
        "https://b.example/sitemap.xml",
        "posts",
        "/blog/",
    )


async def test_kev_discovers_and_keys_documents_on_the_configured_url():
    source = build_source(KevConfig(name="kev", adapter="kev", entry_url="https://m.example/k.json"))

    items = [i async for i in source.discover(datetime(2020, 1, 1, tzinfo=timezone.utc))]
    assert [i.url for i in items] == ["https://m.example/k.json"]

    raw = RawDocument(
        item=items[0],
        content=b'{"vulnerabilities": [{"cveID": "CVE-2026-0001", "shortDescription": "x"}]}',
        content_type="application/json",
        http_status=200,
        fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert source.parse(raw).documents[0].url == "https://m.example/k.json#CVE-2026-0001"


async def test_nvd_queries_the_configured_api_and_limits_its_host():
    source = build_source(NvdConfig(name="nvd", adapter="nvd", entry_url="https://m.example/cves"))

    class FakeFetcher:
        def __init__(self) -> None:
            self.limiter = RecordingLimiter()
            self.urls: list[str] = []

        async def fetch(self, item: DiscoveredItem) -> RawDocument:
            self.urls.append(item.url)
            return RawDocument(
                item=item,
                content=b'{"totalResults": 0}',
                content_type="application/json",
                http_status=200,
                fetched_at=datetime.now(timezone.utc),
            )

    fetcher = FakeFetcher()
    since = datetime.now(timezone.utc) - timedelta(days=1)
    assert [i async for i in source.discover(since, fetcher)] == []
    assert fetcher.urls and all(u.startswith("https://m.example/cves?") for u in fetcher.urls)
    assert fetcher.limiter.limits == {"m.example": source.rate_limit}


def test_register_from_config_skips_disabled_sources(tmp_path):
    path = tmp_path / "sources.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {"name": "on", "adapter": "rss", "entry_url": "https://on.example/feed"},
                    {
                        "name": "off",
                        "adapter": "rss",
                        "entry_url": "https://off.example/feed",
                        "enabled": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    registered = register_from_config(path)

    assert [s.name for s in registered] == ["on"]
    assert [s.name for s in base.all_sources()] == ["on"]


def test_shipped_catalog_registers_every_source():
    register_from_config(SHIPPED)
    assert {s.name for s in base.all_sources()} == {
        "bleepingcomputer", "securityweek", "projectzero", "krebsonsecurity", "thehackernews",
        "therecord", "talos", "sentinelone", "unit42", "microsoft", "malwarebytes", "kev", "nvd",
    }  # fmt: skip


def test_apply_rate_limits_installs_each_limit_on_its_entry_host():
    sources = [
        NewsRssSource("a", "https://a.example/feed", rate_limit=RateLimit(1, 3.0)),
        NvdSource(api="https://nvd.example/cves", rate_limit=RateLimit(1, 6.5)),
    ]
    limiter = RecordingLimiter()

    apply_rate_limits(limiter, sources)

    assert limiter.limits == {"a.example": RateLimit(1, 3.0), "nvd.example": RateLimit(1, 6.5)}


def test_shared_host_gets_the_slower_limit():
    sources = [
        NewsRssSource("fast", "https://same.example/a", rate_limit=RateLimit(2, 1.0)),
        NewsRssSource("slow", "https://same.example/b", rate_limit=RateLimit(1, 4.0)),
    ]
    limiter = RecordingLimiter()

    apply_rate_limits(limiter, sources)

    assert limiter.limits == {"same.example": RateLimit(1, 4.0)}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/sources/test_loader.py -v`
Expected: collection error, `No module named 'crawler.sources.loader'`

- [ ] **Step 3: Implement the adapter changes**

`src/crawler/sources/base.py`: in `class Source(Protocol)`, add after `license: str`:

```python
    # Where discovery starts. The loader installs `rate_limit` on this URL's host.
    entry_url: str
```

`src/crawler/sources/__init__.py`: replace the whole file with:

```python
"""Source adapters. Which sources exist is decided by config/sources.yaml; see loader.py."""
```

`src/crawler/sources/news_rss.py`:
- Module docstring: replace `` `SITES` `` with `config/sources.yaml`. The sentence becomes: "so adding a publication is an entry in config/sources.yaml rather than a new module."
- Delete the `SITES` list and the whole comment block below it ("Only the sites with no better route…" through the `googletag` line). That text now lives in `sources.yaml`.
- Delete the final `for _name, _feed in SITES: register(...)` loop. Change the import `from crawler.sources.base import RateLimit, register` to `from crawler.sources.base import RateLimit`.
- Replace the class header and `__init__` with:

```python
# Deliberately slower than the 1/2s default: these are small publishers, and the crawler
# walks every article in a feed back to back.
DEFAULT_RATE_LIMIT = RateLimit(requests=1, per_seconds=3.0)


class NewsRssSource:
    kind = "feed"

    def __init__(
        self,
        name: str,
        feed_url: str,
        rate_limit: RateLimit = DEFAULT_RATE_LIMIT,
        license: str = "copyrighted",
    ) -> None:
        self.name = name
        self.feed_url = feed_url
        self.entry_url = feed_url
        self.rate_limit = rate_limit
        self.license = license
```

`src/crawler/sources/sitemap.py`:
- Delete the `SITES = [...]` list, the malwarebytes comment under it, and the final `for _site in SITES: register(...)` loop. Change `from crawler.sources.base import register` to nothing; remove that import line.
- Replace the class header and `__init__` with:

```python
class SitemapSource:
    kind = "html"

    def __init__(
        self,
        site: SitemapSite,
        rate_limit: RateLimit = RateLimit(requests=1, per_seconds=2.0),
        license: str = "copyrighted",
    ) -> None:
        self._site = site
        self.name = site.name
        self.entry_url = site.index
        self.rate_limit = rate_limit
        self.license = license
```

`src/crawler/sources/wordpress.py`:
- Delete the `SITES` list (its root-path comment now lives in `sources.yaml`) and the final `register` loop. Change `from crawler.sources.base import RateLimit, register` to `from crawler.sources.base import RateLimit`.
- Replace the class header and `__init__` with:

```python
class WordPressSource:
    kind = "api"

    def __init__(
        self,
        name: str,
        api: str,
        rate_limit: RateLimit = RateLimit(requests=1, per_seconds=2.0),
        license: str = "copyrighted",
    ) -> None:
        self.name = name
        self.api = api
        self.entry_url = api
        self.rate_limit = rate_limit
        self.license = license
```

`src/crawler/sources/kev.py`:
- Delete the final `register(KevSource())`. Change `from crawler.sources.base import RateLimit, register` to `from crawler.sources.base import RateLimit`.
- Replace the class attributes `name`, `kind`, `license`, `rate_limit` (keep `CATALOG_URL`) with:

```python
    kind = "api"

    def __init__(
        self,
        name: str = "kev",
        catalog_url: str = CATALOG_URL,
        rate_limit: RateLimit = RateLimit(requests=1, per_seconds=2.0),
        license: str = "public-domain",
    ) -> None:
        self.name = name
        self.entry_url = catalog_url
        self.rate_limit = rate_limit
        self.license = license
```

- In `discover`, change `url=self.CATALOG_URL` to `url=self.entry_url`. In `parse`, change `url=f"{self.CATALOG_URL}#{cve_id}"` to `url=f"{self.entry_url}#{cve_id}"`. Change the warning `"kev: entry without cveID skipped: %r", entry.get("product")` to `"%s: entry without cveID skipped: %r", self.name, entry.get("product")`.

`src/crawler/sources/nvd.py`:
- Add `from urllib.parse import urlparse`. Delete the `HOST = ...` constant and the final `register(NvdSource())`. Change `from crawler.sources.base import RateLimit, register` to `from crawler.sources.base import RateLimit`.
- Change `_page_url` to take the API base:

```python
def _page_url(api: str, start: datetime, end: datetime, index: int, mode: str, size: int) -> str:
    # Backfill asks "what was published in this window"; an incremental run asks "what changed".
    # They return different sets: a lastMod query misses everything published long ago and
    # never touched since.
    prefix = "pub" if mode == "backfill" else "lastMod"
    return (
        f"{api}?{prefix}StartDate={_stamp(start)}&{prefix}EndDate={_stamp(end)}"
        f"&resultsPerPage={size}&startIndex={index}"
    )
```

- Replace the class attributes `name`, `kind`, `license`, `rate_limit` with:

```python
    kind = "api"

    def __init__(
        self,
        name: str = "nvd",
        api: str = API,
        rate_limit: RateLimit = NO_KEY_LIMIT,
        license: str = "public-domain",
    ) -> None:
        self.name = name
        self.entry_url = api
        self.rate_limit = rate_limit
        self.license = license
```

- In `discover`, change `fetcher.limiter.set_limit(HOST, self.rate_limit)` to `fetcher.limiter.set_limit(urlparse(self.entry_url).netloc, self.rate_limit)`. Change `_page_url(start, end, page * PAGE_SIZE, mode, PAGE_SIZE)` to `_page_url(self.entry_url, start, end, page * PAGE_SIZE, mode, PAGE_SIZE)`. In `_count`, change `_page_url(start, end, 0, mode, 1)` to `_page_url(self.entry_url, start, end, 0, mode, 1)`.

- [ ] **Step 4: Implement the loader** — `src/crawler/sources/loader.py`

```python
"""Turn config/sources.yaml entries into registered Source adapters."""

from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from crawler.core.models import RateLimit
from crawler.core.ratelimit import DomainRateLimiter
from crawler.sources.base import Source, register
from crawler.sources.catalog import (
    CatalogError,
    KevConfig,
    NvdConfig,
    RssConfig,
    SitemapConfig,
    SourceConfig,
    WordPressConfig,
    load_catalog,
)
from crawler.sources.kev import KevSource
from crawler.sources.news_rss import NewsRssSource
from crawler.sources.nvd import NvdSource
from crawler.sources.sitemap import SitemapSite, SitemapSource
from crawler.sources.wordpress import WordPressSource


def build_source(config: SourceConfig) -> Source:
    limit = config.rate_limit.to_rate_limit()
    match config:
        case RssConfig():
            return NewsRssSource(
                config.name, config.entry_url, rate_limit=limit, license=config.license
            )
        case SitemapConfig():
            site = SitemapSite(
                config.name, config.entry_url, config.child_pattern, config.article_pattern
            )
            return SitemapSource(site, rate_limit=limit, license=config.license)
        case WordPressConfig():
            return WordPressSource(
                config.name, config.entry_url, rate_limit=limit, license=config.license
            )
        case KevConfig():
            return KevSource(config.name, config.entry_url, rate_limit=limit, license=config.license)
        case NvdConfig():
            return NvdSource(config.name, config.entry_url, rate_limit=limit, license=config.license)
    raise CatalogError(f"{config.name}: no adapter for {config.adapter!r}")  # pragma: no cover


def register_from_config(path: Path) -> list[Source]:
    """Register every enabled source in `path` and return them in file order."""
    sources = [build_source(c) for c in load_catalog(path) if c.enabled]
    for source in sources:
        register(source)
    return sources


def _rate(limit: RateLimit) -> float:
    return limit.requests / limit.per_seconds


def apply_rate_limits(limiter: DomainRateLimiter, sources: Iterable[Source]) -> None:
    """Install each source's declared limit on the host its entry URL points at.

    Two sources on one host get the slower of their limits: the publisher sees one crawler.
    """
    chosen: dict[str, RateLimit] = {}
    for source in sources:
        host = urlparse(source.entry_url).netloc
        current = chosen.get(host)
        if current is None or _rate(source.rate_limit) < _rate(current):
            chosen[host] = source.rate_limit
    for host, limit in chosen.items():
        limiter.set_limit(host, limit)
```

- [ ] **Step 5: Wire the CLI** — `src/crawler/cli.py`

Replace these two lines:

```python
# Importing the package runs its __init__, which registers every source adapter.
from crawler.sources import base as source_registry
```

with:

```python
from crawler.sources import base as source_registry
from crawler.sources.catalog import CatalogError
from crawler.sources.loader import apply_rate_limits, register_from_config
```

Add this helper above `_targets`:

```python
def _load_sources() -> None:
    """Register every enabled source in the catalog. A bad catalog stops the command here."""
    try:
        register_from_config(get_settings().sources_config)
    except CatalogError as exc:
        typer.secho(f"Invalid source catalog: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc
```

In `_targets`, make `_load_sources()` the first statement of the function body, after the docstring. In `sources_list`, make `_load_sources()` the first statement after the docstring. In `build_fetcher`, add this line right after the `limiter = ...` line:

```python
    apply_rate_limits(limiter, source_registry.all_sources())
```

- [ ] **Step 6: Run the new and existing source tests**

Run: `uv run pytest tests/sources -v`
Expected: all PASS, including the untouched `test_news_rss.py`, `test_kev.py`, `test_registry.py`

- [ ] **Step 7: Run the whole suite and the CLI**

Run: `uv run pytest -q`
Expected: no failures beyond the known DB `OperationalError`s.

Run: `uv run crawler sources list`
Expected: 13 lines, starting `bleepingcomputer feed   copyrighted`, ending `nvd              api    public-domain`

- [ ] **Step 8: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add src/crawler/sources src/crawler/cli.py tests/sources/test_loader.py
git commit -m "feat: build sources from config/sources.yaml and enforce their rate limits

Each source's declared rate_limit is now installed on its host; until now only NVD
applied its own and every other host ran at the 1-per-2s default.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `config/ontology.json` and the `Ontology` loader

**Files:**
- Create: `config/ontology.json`
- Create: `src/crawler/extraction/__init__.py`
- Create: `src/crawler/extraction/ontology.py`
- Create: `tests/extraction/conftest.py`
- Create: `tests/extraction/test_ontology.py`
- Modify: `src/crawler/config.py` (add `ontology_path`)

**Interfaces:**
- Produces:
  - `class OntologyError(ValueError)`
  - `EntityType(name: str, label: str, description: str)` (frozen dataclass)
  - `Relation(name: str, inverse: str, description: str, pairs: frozenset[tuple[str, str]], generic_target: str | None = None)`
  - `class Ontology` with attributes `version: str`, `entity_types: tuple[EntityType, ...]`, `relations: tuple[Relation, ...]`, `entity_names: tuple[str, ...]` (file order), `allowed_pairs: dict[str, list[tuple[str, str]]]` (stored name → every allowed (source, target), generic rules expanded); methods `canonical(relation: str) -> tuple[str | None, bool]`, `allowed(source_type: str, relation: str, target_type: str) -> bool` (accepts inverse names)
  - `parse_ontology(data: object, source: str = "ontology.json") -> Ontology`
  - `load_ontology(path: Path) -> Ontology` (cached per path)
  - pytest fixture `ontology` (session scope, the shipped file) in `tests/extraction/conftest.py`
  - `Settings.ontology_path: Path = Path("config/ontology.json")`

**Interpretation of the spec table, fixed here:**
- `A/B -> rel -> C/D` allows every combination.
- `Attack technique -> mitigated-by -> Security team` and `Security team -> mitigates -> Vulnerability` are one relation family. It is stored as `mitigates` (SecurityTeam → AttackTechnique, SecurityTeam → Vulnerability) with inverse `mitigated-by`.
- "Any Entity → occurs-at → Time" and "Any Entity → located-in → Location" are generic rules. They apply only to source types that have no specific relation to that target. This is the extractor's existing behaviour: a group has `operates-in`, so `located-in` is not offered for it, and a group has `active-at`, so `occurs-at` is not. An entity never relates to its own type through a generic rule.
- Inverse names are the extractor's existing ones. They let the validator accept an LLM or rules triple written the other way round and rewrite it into the stored direction.

- [ ] **Step 1: Write `config/ontology.json`**

```json
{
  "version": "2026-10-04",
  "entity_types": [
    {"name": "ThreatActor", "label": "Threat actor",
     "description": "An individual attacker, persona or unnamed actor (e.g. 'a Russian-speaking hacker', 'the operator'). Named APT groups are ThreatGroup."},
    {"name": "ThreatGroup", "label": "Threat group",
     "description": "A named hacking group, APT or crime gang (APT28, Lazarus Group, FIN7, OilRig)."},
    {"name": "Malware", "label": "Malware",
     "description": "Malicious software: backdoors, RATs, trojans, ransomware, loaders (X-Agent, PlugX, WannaCry, Emotet)."},
    {"name": "AttackTechnique", "label": "Attack technique",
     "description": "A specific adversary technique, usually a MITRE ATT&CK technique or ID (Spearphishing Attachment, T1566.001, credential dumping)."},
    {"name": "Vulnerability", "label": "Vulnerability",
     "description": "A software weakness or exploit, including CVE IDs (CVE-2017-11882, a zero-day in Flash, EternalBlue)."},
    {"name": "Software", "label": "Software",
     "description": "Legitimate software or a product that is attacked, abused or vulnerable (Microsoft Office, Windows, Adobe Flash)."},
    {"name": "Tool", "label": "Tool",
     "description": "Dual-use or offensive tooling that is not malware itself (Mimikatz, PsExec, Impacket, PowerShell)."},
    {"name": "Organization", "label": "Organization",
     "description": "A targeted or involved company, agency or sector (banks, government agencies, Microsoft, the energy sector)."},
    {"name": "AttackPattern", "label": "Attack pattern",
     "description": "A general method or style of attack not tied to one technique (phishing, watering hole attacks, supply-chain attack, brute force)."},
    {"name": "FileHash", "label": "File/hash",
     "description": "A file name, file sample or hash (MD5/SHA1/SHA256) (invoice.doc, svchost.exe, d41d8cd98f00b204e9800998ecf8427e)."},
    {"name": "NetworkInfra", "label": "Network infrastructure",
     "description": "An IP address, domain, URL or server used in attacks, including defanged forms (185.12.45[.]6, evil[.]com, C2 server)."},
    {"name": "Asset", "label": "Asset/system",
     "description": "A victim system, device or network (email servers, ICS systems, endpoints, domain controllers)."},
    {"name": "SecurityTeam", "label": "Security team",
     "description": "A security vendor, research team or CERT (FireEye, Kaspersky Lab, Unit 42, US-CERT)."},
    {"name": "Time", "label": "Time",
     "description": "A date, year, month or period (2017, March 2019, late 2018)."},
    {"name": "Location", "label": "Location",
     "description": "A country, region, city or nationality (Russia, the Middle East, Ukrainian)."}
  ],
  "relations": [
    {"name": "alias-of", "inverse": "alias-of",
     "description": "two names for the same actor or group",
     "pairs": [["ThreatActor", "ThreatActor"], ["ThreatActor", "ThreatGroup"],
               ["ThreatGroup", "ThreatActor"], ["ThreatGroup", "ThreatGroup"]]},
    {"name": "uses", "inverse": "used-by",
     "description": "an actor, group or technique uses malware, a tool, software, a technique or a pattern",
     "pairs": [["ThreatActor", "Malware"], ["ThreatActor", "AttackTechnique"], ["ThreatActor", "Tool"],
               ["ThreatActor", "AttackPattern"], ["ThreatActor", "Software"],
               ["ThreatGroup", "Malware"], ["ThreatGroup", "AttackTechnique"], ["ThreatGroup", "Tool"],
               ["ThreatGroup", "AttackPattern"], ["ThreatGroup", "Software"],
               ["AttackTechnique", "Tool"], ["AttackTechnique", "Malware"]]},
    {"name": "targets", "inverse": "targeted-by",
     "description": "an actor, group or technique targets an organization, asset or vulnerability",
     "pairs": [["ThreatActor", "Organization"], ["ThreatActor", "Asset"],
               ["ThreatGroup", "Organization"], ["ThreatGroup", "Asset"],
               ["AttackTechnique", "Vulnerability"], ["AttackTechnique", "Asset"]]},
    {"name": "operates-in", "inverse": "operation-area-of",
     "description": "an actor or group is active in a location",
     "pairs": [["ThreatActor", "Location"], ["ThreatGroup", "Location"]]},
    {"name": "originated-from", "inverse": "origin-of",
     "description": "an actor or group comes from a location",
     "pairs": [["ThreatActor", "Location"], ["ThreatGroup", "Location"]]},
    {"name": "active-at", "inverse": "activity-time-of",
     "description": "an actor or group is active at a time",
     "pairs": [["ThreatActor", "Time"], ["ThreatGroup", "Time"]]},
    {"name": "variant-of", "inverse": "has-variant",
     "description": "malware or a tool is a variant of malware or a tool; a technique or pattern is a variant of a technique or pattern",
     "pairs": [["Malware", "Malware"], ["Malware", "Tool"], ["Tool", "Malware"], ["Tool", "Tool"],
               ["AttackTechnique", "AttackTechnique"], ["AttackTechnique", "AttackPattern"],
               ["AttackPattern", "AttackTechnique"], ["AttackPattern", "AttackPattern"]]},
    {"name": "sub_technique_of", "inverse": "has_sub_technique",
     "description": "a technique or pattern is a sub-technique of a technique or pattern",
     "pairs": [["AttackTechnique", "AttackTechnique"], ["AttackTechnique", "AttackPattern"],
               ["AttackPattern", "AttackTechnique"], ["AttackPattern", "AttackPattern"]]},
    {"name": "drops", "inverse": "dropped-by",
     "description": "malware drops a file",
     "pairs": [["Malware", "FileHash"]]},
    {"name": "exploits", "inverse": "exploited-by",
     "description": "malware or a tool exploits a vulnerability",
     "pairs": [["Malware", "Vulnerability"], ["Tool", "Vulnerability"]]},
    {"name": "affects", "inverse": "affected-by",
     "description": "malware or a vulnerability affects software or an asset",
     "pairs": [["Malware", "Software"], ["Malware", "Asset"],
               ["Vulnerability", "Software"], ["Vulnerability", "Asset"]]},
    {"name": "communicates-with", "inverse": "contacted-by",
     "description": "malware or a tool communicates with network infrastructure",
     "pairs": [["Malware", "NetworkInfra"], ["Tool", "NetworkInfra"]]},
    {"name": "contains", "inverse": "contained-in",
     "description": "software contains a vulnerability",
     "pairs": [["Software", "Vulnerability"]]},
    {"name": "runs-on", "inverse": "hosts",
     "description": "software runs on an asset/system",
     "pairs": [["Software", "Asset"]]},
    {"name": "mitigates", "inverse": "mitigated-by",
     "description": "a security team mitigates a technique or a vulnerability",
     "pairs": [["SecurityTeam", "AttackTechnique"], ["SecurityTeam", "Vulnerability"]]},
    {"name": "remediated-by", "inverse": "remediates",
     "description": "a vulnerability is remediated by software (a patch or update)",
     "pairs": [["Vulnerability", "Software"]]},
    {"name": "belongs-to", "inverse": "owns",
     "description": "an asset or network infrastructure belongs to an organization",
     "pairs": [["Asset", "Organization"], ["NetworkInfra", "Organization"]]},
    {"name": "located-in", "inverse": "location-of",
     "description": "something is located in a location (any entity: only when no more specific relation to a location fits)",
     "pairs": [["Asset", "Location"], ["NetworkInfra", "Location"]],
     "generic_target": "Location"},
    {"name": "monitored-by", "inverse": "monitors",
     "description": "an asset/system is monitored by a security team",
     "pairs": [["Asset", "SecurityTeam"]]},
    {"name": "indicates", "inverse": "indicated-by",
     "description": "a file/hash indicates malware or a threat actor",
     "pairs": [["FileHash", "Malware"], ["FileHash", "ThreatActor"]]},
    {"name": "downloads-from", "inverse": "download-source-of",
     "description": "a file downloads from network infrastructure",
     "pairs": [["FileHash", "NetworkInfra"]]},
    {"name": "utilized-by", "inverse": "utilizes",
     "description": "network infrastructure is utilized by an actor, group or malware",
     "pairs": [["NetworkInfra", "ThreatActor"], ["NetworkInfra", "ThreatGroup"],
               ["NetworkInfra", "Malware"]]},
    {"name": "investigates", "inverse": "investigated-by",
     "description": "a security team investigates an actor or group",
     "pairs": [["SecurityTeam", "ThreatActor"], ["SecurityTeam", "ThreatGroup"]]},
    {"name": "detects", "inverse": "detected-by",
     "description": "a security team detects malware, a vulnerability or an attack pattern",
     "pairs": [["SecurityTeam", "Malware"], ["SecurityTeam", "Vulnerability"],
               ["SecurityTeam", "AttackPattern"]]},
    {"name": "patches", "inverse": "patched-by",
     "description": "a security team patches an asset/system",
     "pairs": [["SecurityTeam", "Asset"]]},
    {"name": "occurs-at", "inverse": "time-of",
     "description": "something happens at a time (any entity: only when no more specific relation to a time fits)",
     "pairs": [],
     "generic_target": "Time"}
  ]
}
```

- [ ] **Step 2: Write the failing tests**

`tests/extraction/conftest.py`:

```python
from pathlib import Path

import pytest

from crawler.extraction.ontology import Ontology, load_ontology

SHIPPED_ONTOLOGY = Path(__file__).resolve().parents[2] / "config" / "ontology.json"


@pytest.fixture(scope="session")
def ontology() -> Ontology:
    return load_ontology(SHIPPED_ONTOLOGY)
```

`tests/extraction/test_ontology.py`:

```python
import json

import pytest

from crawler.extraction.ontology import OntologyError, load_ontology, parse_ontology

SPEC_LABELS = [
    "Threat actor", "Threat group", "Malware", "Attack technique", "Vulnerability", "Software",
    "Tool", "Organization", "Attack pattern", "File/hash", "Network infrastructure",
    "Asset/system", "Security team", "Time", "Location",
]  # fmt: skip

ACTORS = ("ThreatActor", "ThreatGroup")
MAL_TOOL = ("Malware", "Tool")
TECH = ("AttackTechnique", "AttackPattern")

# CTI_INTEGRATION.md, Objective 2, every line spelled out. "A/B" means every combination.
SPEC_TRIPLES = [
    *[(a, "alias-of", b) for a in ACTORS for b in ACTORS],
    *[
        (a, "uses", t)
        for a in ACTORS
        for t in ("Malware", "AttackTechnique", "Tool", "AttackPattern", "Software")
    ],
    *[(a, "targets", t) for a in ACTORS for t in ("Organization", "Asset")],
    *[(a, r, "Location") for a in ACTORS for r in ("operates-in", "originated-from")],
    *[(a, "active-at", "Time") for a in ACTORS],
    *[(a, "variant-of", b) for a in MAL_TOOL for b in MAL_TOOL],
    ("Malware", "drops", "FileHash"),
    *[(a, "exploits", "Vulnerability") for a in MAL_TOOL],
    *[("Malware", "affects", t) for t in ("Software", "Asset")],
    *[(a, "communicates-with", "NetworkInfra") for a in MAL_TOOL],
    ("Software", "contains", "Vulnerability"),
    ("Software", "runs-on", "Asset"),
    *[(a, r, b) for a in TECH for b in TECH for r in ("sub_technique_of", "variant-of")],
    *[("AttackTechnique", "uses", t) for t in ("Tool", "Malware")],
    *[("AttackTechnique", "targets", t) for t in ("Vulnerability", "Asset")],
    ("AttackTechnique", "mitigated-by", "SecurityTeam"),
    *[("Vulnerability", "affects", t) for t in ("Software", "Asset")],
    ("Vulnerability", "remediated-by", "Software"),
    ("Asset", "belongs-to", "Organization"),
    ("Asset", "located-in", "Location"),
    ("Asset", "monitored-by", "SecurityTeam"),
    *[("FileHash", "indicates", t) for t in ("Malware", "ThreatActor")],
    ("FileHash", "downloads-from", "NetworkInfra"),
    ("NetworkInfra", "belongs-to", "Organization"),
    ("NetworkInfra", "located-in", "Location"),
    *[("NetworkInfra", "utilized-by", t) for t in (*ACTORS, "Malware")],
    *[("SecurityTeam", "investigates", t) for t in ACTORS],
    *[("SecurityTeam", "detects", t) for t in ("Malware", "Vulnerability", "AttackPattern")],
    ("SecurityTeam", "mitigates", "Vulnerability"),
    ("SecurityTeam", "patches", "Asset"),
]


def test_shipped_ontology_has_exactly_the_fifteen_spec_types(ontology):
    assert [t.label for t in ontology.entity_types] == SPEC_LABELS
    assert len(set(ontology.entity_names)) == 15


@pytest.mark.parametrize("triple", SPEC_TRIPLES, ids=lambda t: " ".join(t))
def test_every_spec_triple_is_allowed(ontology, triple):
    assert ontology.allowed(*triple)


def test_specific_pairs_are_exactly_the_spec_table(ontology):
    def stored(source, relation, target):
        name, flipped = ontology.canonical(relation)
        return (target, name, source) if flipped else (source, name, target)

    in_file = {(s, r.name, t) for r in ontology.relations for s, t in r.pairs}
    assert in_file == {stored(*t) for t in SPEC_TRIPLES}


@pytest.mark.parametrize(
    "triple",
    [
        ("Malware", "occurs-at", "Time"),
        ("Vulnerability", "occurs-at", "Time"),
        ("Organization", "located-in", "Location"),
        ("SecurityTeam", "located-in", "Location"),
    ],
)
def test_any_entity_relations_reach_time_and_location(ontology, triple):
    assert ontology.allowed(*triple)


@pytest.mark.parametrize(
    "triple",
    [
        ("ThreatGroup", "located-in", "Location"),  # operates-in / originated-from fit
        ("ThreatActor", "occurs-at", "Time"),  # active-at fits
        ("Time", "occurs-at", "Time"),
        ("Location", "located-in", "Location"),
    ],
)
def test_generic_relations_yield_to_specific_ones(ontology, triple):
    assert not ontology.allowed(*triple)


@pytest.mark.parametrize(
    "triple",
    [
        ("Malware", "targets", "Organization"),
        ("Tool", "drops", "FileHash"),
        ("AttackPattern", "uses", "Tool"),
        ("Software", "exploits", "Vulnerability"),
        ("Organization", "uses", "Malware"),
        ("Malware", "loves", "Tool"),
        ("Gadget", "uses", "Malware"),
    ],
)
def test_triples_outside_the_spec_are_refused(ontology, triple):
    assert not ontology.allowed(*triple)


def test_inverse_names_are_checked_in_the_stored_direction(ontology):
    assert ontology.canonical("used-by") == ("uses", True)
    assert ontology.canonical("uses") == ("uses", False)
    assert ontology.canonical("loves") == (None, False)
    assert ontology.allowed("Malware", "used-by", "ThreatGroup")
    assert not ontology.allowed("ThreatGroup", "used-by", "Malware")


def minimal(**relation) -> dict:
    return {
        "version": "t",
        "entity_types": [
            {"name": "Malware", "label": "Malware", "description": "m"},
            {"name": "Tool", "label": "Tool", "description": "t"},
        ],
        "relations": [
            {
                "name": "uses",
                "inverse": "used-by",
                "description": "d",
                "pairs": [["Malware", "Tool"]],
                **relation,
            }
        ],
    }


@pytest.mark.parametrize(
    "data, message",
    [
        (minimal(pairs=[["Malware", "Gadget"]]), "unknown entity type Gadget"),
        (minimal(pairs=[], generic_target="Gadget"), "unknown entity type Gadget"),
        (minimal(pairs=[]), "allows no pairs"),
        (minimal(inverse="uses"), None),  # self-inverse is legal (alias-of)
        (minimal(extra="x"), "extra"),
        ({**minimal(), "version": ""}, "version"),
    ],
)
def test_parse_ontology_checks_consistency(data, message):
    if message is None:
        parse_ontology(data)
        return
    with pytest.raises(OntologyError, match=message):
        parse_ontology(data)


def test_duplicate_entity_types_are_refused():
    data = minimal()
    data["entity_types"].append({"name": "Tool", "label": "again", "description": "d"})
    with pytest.raises(OntologyError, match="duplicate entity type Tool"):
        parse_ontology(data)


def test_relation_names_must_not_collide():
    data = minimal()
    data["relations"].append(
        {"name": "drops", "inverse": "used-by", "description": "d", "pairs": [["Malware", "Tool"]]}
    )
    with pytest.raises(OntologyError, match="used-by"):
        parse_ontology(data)


def test_load_ontology_reports_bad_files(tmp_path):
    with pytest.raises(OntologyError, match="not found"):
        load_ontology(tmp_path / "missing.json")

    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(OntologyError, match="not valid JSON"):
        load_ontology(bad)

    good = tmp_path / "good.json"
    good.write_text(json.dumps(minimal()), encoding="utf-8")
    assert load_ontology(good).entity_names == ("Malware", "Tool")
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/extraction/test_ontology.py -v`
Expected: collection error, `No module named 'crawler.extraction'`

- [ ] **Step 4: Implement**

`src/crawler/extraction/__init__.py`:

```python
"""CTI entity and relation extraction from crawled documents (`crawler extract`)."""
```

`src/crawler/extraction/ontology.py`:

```python
"""The CTI ontology: which entity types exist and which relations may join them.

config/ontology.json is the single source of truth. The LLM's response schema, its prompt and
the validator that runs afterwards are all generated from one loaded Ontology, so the extractor
cannot emit a type or a triple the file does not list.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TYPE_NAME = r"^[A-Z][A-Za-z0-9]{1,39}$"  # becomes a BIO-style label, so one word
RELATION_NAME = r"^[a-z][a-z0-9_-]{1,39}$"


class OntologyError(ValueError):
    """config/ontology.json is missing, malformed, or internally inconsistent."""


class _EntityTypeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=TYPE_NAME)
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)


class _RelationFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=RELATION_NAME)
    inverse: str = Field(pattern=RELATION_NAME)
    description: str = Field(min_length=1)
    pairs: list[tuple[str, str]] = []
    generic_target: str | None = None


class _OntologyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1)
    entity_types: list[_EntityTypeFile] = Field(min_length=1)
    relations: list[_RelationFile]


@dataclass(frozen=True)
class EntityType:
    name: str
    label: str
    description: str


@dataclass(frozen=True)
class Relation:
    name: str
    inverse: str
    description: str
    pairs: frozenset[tuple[str, str]]
    generic_target: str | None = None


class Ontology:
    def __init__(
        self,
        version: str,
        entity_types: Sequence[EntityType],
        relations: Sequence[Relation],
    ) -> None:
        self.version = version
        self.entity_types = tuple(entity_types)
        self.relations = tuple(relations)
        self.entity_names = tuple(t.name for t in self.entity_types)
        self._forward = {r.name: r for r in self.relations}
        self._inverse = {r.inverse: r for r in self.relations if r.inverse != r.name}
        self.allowed_pairs = self._expand()

    def _expand(self) -> dict[str, list[tuple[str, str]]]:
        """{relation: [(source, target), ...]} with every generic rule spelled out.

        "Any entity -> located-in -> Location" applies only to source types with no specific
        relation to Location: a group has operates-in, so "APT28 located-in Russia" is not
        offered and "APT28 operates-in Russia" is.
        """
        order = {name: n for n, name in enumerate(self.entity_names)}
        specific = {pair for r in self.relations for pair in r.pairs}
        out: dict[str, list[tuple[str, str]]] = {}
        for r in self.relations:
            pairs = set(r.pairs)
            if r.generic_target is not None:
                pairs |= {
                    (s, r.generic_target)
                    for s in self.entity_names
                    if s != r.generic_target and (s, r.generic_target) not in specific
                }
            out[r.name] = sorted(pairs, key=lambda p: (order[p[0]], order[p[1]]))
        return out

    def canonical(self, relation: str) -> tuple[str | None, bool]:
        """(stored name, flipped). `flipped` means the caller's source and target swap."""
        if relation in self._forward:
            return relation, False
        if relation in self._inverse:
            return self._inverse[relation].name, True
        return None, False

    def allowed(self, source_type: str, relation: str, target_type: str) -> bool:
        name, flipped = self.canonical(relation)
        if name is None:
            return False
        if flipped:
            source_type, target_type = target_type, source_type
        return (source_type, target_type) in self.allowed_pairs[name]


def parse_ontology(data: object, source: str = "ontology.json") -> Ontology:
    try:
        parsed = _OntologyFile.model_validate(data)
    except ValidationError as exc:
        raise OntologyError(f"{source}: {exc}") from exc

    names = [t.name for t in parsed.entity_types]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise OntologyError(f"{source}: duplicate entity type {', '.join(dupes)}")
    known = set(names)

    taken: set[str] = set()
    relations: list[Relation] = []
    for r in parsed.relations:
        words = {r.name, r.inverse}
        clash = sorted(words & taken)
        if clash:
            raise OntologyError(f"{source}: relation name {', '.join(clash)} is used twice")
        taken |= words

        unknown = sorted({t for pair in r.pairs for t in pair} - known)
        if r.generic_target is not None and r.generic_target not in known:
            unknown.append(r.generic_target)
        if unknown:
            raise OntologyError(
                f"{source}: relation {r.name} names unknown entity type {', '.join(unknown)}"
            )
        if not r.pairs and r.generic_target is None:
            raise OntologyError(f"{source}: relation {r.name} allows no pairs")

        relations.append(
            Relation(r.name, r.inverse, r.description, frozenset(r.pairs), r.generic_target)
        )

    types = [EntityType(t.name, t.label, t.description) for t in parsed.entity_types]
    return Ontology(parsed.version, types, relations)


@lru_cache(maxsize=None)
def load_ontology(path: Path) -> Ontology:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise OntologyError(f"{path}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise OntologyError(f"{path}: not valid JSON ({exc})") from exc
    return parse_ontology(data, str(path))
```

In `src/crawler/config.py`, add to `Settings` after `sources_config`:

```python
    ontology_path: Path = Path("config/ontology.json")
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/extraction/test_ontology.py -v`
Expected: all PASS

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add config/ontology.json src/crawler/extraction src/crawler/config.py tests/extraction
git commit -m "feat: strict 15-type CTI ontology in config/ontology.json

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Port the tokenizer, regex patterns and dictionary matcher

**Files:**
- Create: `src/crawler/extraction/spans.py`
- Create: `src/crawler/extraction/tokenizer.py`
- Create: `src/crawler/extraction/patterns.py` (copied, type hints added)
- Create: `src/crawler/extraction/rules.py`
- Create: `src/crawler/extraction/resources/entities.json` (copied)
- Create: `tests/extraction/test_tokenizer.py`, `test_patterns.py`, `test_rules.py` (copied, imports changed, one guard test added)
- Modify: `pyproject.toml` (ruff per-file ignores)

**Interfaces:**
- Consumes: `ontology` fixture (Task 3)
- Produces:
  - `spans.py`: `Span = list[Any]` (`[start_token, end_token, surface, entity_type]`), `IndexTriple = tuple[int, str, int]`, `Entity = tuple[str, str]` (text, type), `SurfaceTriple = tuple[str, str, str]` (source text, relation, target text)
  - `tokenize(text: str, split_final_period: bool = True) -> str`; `split_sentences(text: str) -> list[str]`
  - `match_token(token: str) -> str | None`; `find_times(tokens: list[str]) -> list[tuple[int, int]]`
  - `RuleMatcher(entries)`, `.find(text: str, types: Collection[str] | None = None) -> tuple[list[Span], list[IndexTriple]]`, attributes `exact`, `folded: dict[tuple[str, ...], tuple[str, str]]`; `load_matcher(path: Path = DICTIONARY_PATH) -> RuleMatcher`

- [ ] **Step 1: Copy the tests and the data, fix imports**

```bash
mkdir -p src/crawler/extraction/resources
cp ../text-extractor/dictionaries/entities.json src/crawler/extraction/resources/entities.json
cp ../text-extractor/tests/test_tokenizer.py tests/extraction/test_tokenizer.py
cp ../text-extractor/tests/test_patterns.py tests/extraction/test_patterns.py
cp ../text-extractor/tests/test_rules.py tests/extraction/test_rules.py
sed -i 's/^from tokenizer import/from crawler.extraction.tokenizer import/' tests/extraction/test_tokenizer.py
sed -i 's/^from extractors.patterns import/from crawler.extraction.patterns import/' tests/extraction/test_patterns.py
sed -i 's/^from extractors.rules import/from crawler.extraction.rules import/' tests/extraction/test_rules.py
```

Append to `tests/extraction/test_rules.py` (and add `from crawler.extraction.rules import load_matcher` to its imports):

```python
def test_shipped_dictionary_and_patterns_only_use_ontology_types(ontology):
    matcher = load_matcher()
    dictionary_types = {t for t, _ in [*matcher.exact.values(), *matcher.folded.values()]}
    pattern_types = {"NetworkInfra", "FileHash", "Vulnerability", "AttackTechnique", "Time"}

    assert dictionary_types | pattern_types <= set(ontology.entity_names)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/extraction/test_tokenizer.py tests/extraction/test_patterns.py tests/extraction/test_rules.py -v`
Expected: collection errors, `No module named 'crawler.extraction.tokenizer'` (and `.patterns`, `.rules`)

- [ ] **Step 3: Implement**

`src/crawler/extraction/spans.py`:

```python
"""Shapes passed between the extraction stages."""

from typing import Any

# [start_token, end_token, surface, entity_type]: a list, because the rules, the LLM merge and
# the validator all read and compare spans positionally (the DNRTI format they came from).
Span = list[Any]
# (source_span_index, relation, target_span_index)
IndexTriple = tuple[int, str, int]
# (entity_text, entity_type)
Entity = tuple[str, str]
# (source_text, relation, target_text)
SurfaceTriple = tuple[str, str, str]
```

`src/crawler/extraction/tokenizer.py`:

```python
"""Tokenize text into the DNRTI style: space-separated tokens, punctuation split off.

Tokenizing only inserts spaces; it never rewrites a character. Every token is therefore a
substring of the input, in order, which is what lets the pipeline map tokens back to
character offsets.
"""

import re

LEADING = set('"([{“«')
TRAILING = set('",;:!?)]}”»')
FINAL = TRAILING | {"."}  # a period is only split off the last token of a sentence


def _split_token(token: str, trailing: set[str]) -> list[str]:
    lead: list[str] = []
    tail: list[str] = []
    while len(token) > 1 and token[0] in LEADING:
        lead.append(token[0])
        token = token[1:]
    while len(token) > 1 and token[-1] in trailing:
        tail.insert(0, token[-1])
        token = token[:-1]
    possessive = re.fullmatch(r"(.+)(['’]s)", token)
    if possessive:
        return lead + [possessive.group(1), possessive.group(2)] + tail
    return lead + [token] + tail


def tokenize(text: str, split_final_period: bool = True) -> str:
    words = text.split()
    tokens: list[str] = []
    for n, word in enumerate(words):
        last = split_final_period and n == len(words) - 1
        tokens.extend(_split_token(word, FINAL if last else TRAILING))
    return " ".join(tokens)


ABBREVIATIONS = {
    "e.g.", "i.e.", "etc.", "vs.", "cf.", "al.", "approx.", "no.", "fig.", "inc.", "ltd.",
    "corp.", "co.", "mr.", "ms.", "dr.", "u.s.", "u.k.", "e.u.", "u.n.",
    "jan.", "feb.", "mar.", "apr.", "jun.", "jul.", "aug.", "sep.", "sept.", "oct.", "nov.",
    "dec.",
}  # fmt: skip


def _ends_sentence(before: str, after: str) -> bool:
    """Whether a [.!?] at the end of `before` ends the sentence, given the text `after` it."""
    if after[:1].islower():
        return False
    last = before.split()[-1].lower() if before.split() else ""
    return last not in ABBREVIATIONS and not re.fullmatch(r"[a-z]\.", last)


def split_sentences(text: str) -> list[str]:
    text = text.strip()
    sentences: list[str] = []
    start = 0
    for gap in re.finditer(r"(?<=[.!?])\s+", text):
        if _ends_sentence(text[start : gap.start()], text[gap.end() :]):
            sentences.append(text[start : gap.start()])
            start = gap.end()
    sentences.append(text[start:])
    return [s for s in sentences if s]
```

`src/crawler/extraction/patterns.py`: copy, then add type hints to its three functions:

```bash
cp ../text-extractor/extractors/patterns.py src/crawler/extraction/patterns.py
sed -i 's/^def match_token(token):/def match_token(token: str) -> str | None:/' src/crawler/extraction/patterns.py
sed -i 's/^def _is_month(token):/def _is_month(token: str) -> bool:/' src/crawler/extraction/patterns.py
sed -i 's/^def find_times(tokens):/def find_times(tokens: list[str]) -> list[tuple[int, int]]:/' src/crawler/extraction/patterns.py
grep -n "^def " src/crawler/extraction/patterns.py
```

Expected `grep` output: the three signatures with hints.

`src/crawler/extraction/rules.py`:

```python
"""Rule-based entity finder: regex patterns, then dates, then MITRE ATT&CK dictionary names.

RuleMatcher.find(text, types) works on tokenized text and returns
    spans:    [[start, end, surface, type], ...] sorted by position
    triples:  [(i, "alias-of", j), ...] between spans (by index) that are different
              names of the same ATT&CK group
Each token belongs to at most one span; earlier stages win, and dictionary names
match longest first.
"""

import json
from collections.abc import Collection, Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from crawler.extraction.patterns import find_times, match_token
from crawler.extraction.spans import IndexTriple, Span
from crawler.extraction.tokenizer import tokenize

DICTIONARY_PATH = Path(__file__).resolve().parent / "resources" / "entities.json"


class RuleMatcher:
    def __init__(self, entries: Iterable[dict[str, Any]]) -> None:
        self.exact: dict[tuple[str, ...], tuple[str, str]] = {}
        self.folded: dict[tuple[str, ...], tuple[str, str]] = {}
        for e in entries:
            key = tuple(tokenize(e["name"], split_final_period=False).split())
            if not key:
                continue
            if e.get("case_sensitive", True):
                self.exact.setdefault(key, (e["type"], e["id"]))
            else:
                self.folded.setdefault(tuple(t.lower() for t in key), (e["type"], e["id"]))
        self.max_len = max(map(len, [*self.exact, *self.folded]), default=0)

    def _lookup(self, key: tuple[str, ...]) -> tuple[str, str] | None:
        return self.exact.get(key) or self.folded.get(tuple(t.lower() for t in key))

    def find(
        self, text: str, types: Collection[str] | None = None
    ) -> tuple[list[Span], list[IndexTriple]]:
        tokens = text.split()
        claimed = [False] * len(tokens)
        found: list[tuple[int, int, str, str | None]] = []

        def claim(start: int, end: int, type_: str, id_: str | None = None) -> bool:
            if (types is None or type_ in types) and not any(claimed[start:end]):
                claimed[start:end] = [True] * (end - start)
                found.append((start, end, type_, id_))
                return True
            return False

        for i, token in enumerate(tokens):
            type_ = match_token(token)
            if type_:
                claim(i, i + 1, type_)
        for start, end in find_times(tokens):
            claim(start, end, "Time")
        i = 0
        while i < len(tokens):
            for length in range(min(self.max_len, len(tokens) - i), 0, -1):
                hit = self._lookup(tuple(tokens[i : i + length]))
                if hit and claim(i, i + length, *hit):
                    i += length
                    break
            else:
                i += 1

        found.sort()
        spans: list[Span] = [[s, e, " ".join(tokens[s:e]), t] for s, e, t, _ in found]
        triples: list[IndexTriple] = [
            (j, "alias-of", i)
            for i in range(len(found))
            for j in range(i)
            if found[i][2] == found[j][2] == "ThreatGroup"
            and found[i][3] == found[j][3]
            and spans[i][2] != spans[j][2]
        ]
        return spans, triples


@lru_cache(maxsize=None)
def load_matcher(path: Path = DICTIONARY_PATH) -> RuleMatcher:
    return RuleMatcher(json.loads(Path(path).read_text(encoding="utf-8")))
```

Note: `found.sort()` compares the tuples; `None` ids only compare when `(start, end, type)` tie, which cannot happen because a token is claimed at most once.

Add to `pyproject.toml` under `[tool.ruff.lint]`:

```toml
[tool.ruff.lint.per-file-ignores]
# Ported from text-extractor: regexes, TLD tables and test sentences that read worse wrapped.
"src/crawler/extraction/patterns.py" = ["E501"]
"tests/extraction/*" = ["E501"]
```

- [ ] **Step 4: Format the ported files, run the tests**

```bash
uv run ruff format src/crawler/extraction tests/extraction
uv run ruff check --fix src/crawler/extraction tests/extraction
uv run pytest tests/extraction -v
```

Expected: ruff clean; all PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/crawler/extraction tests/extraction
git commit -m "feat: port tokenizer, regex patterns and ATT&CK dictionary matcher

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Span placement, character offsets, and the ontology validator

**Files:**
- Create: `src/crawler/extraction/formatter.py`
- Create: `src/crawler/extraction/validator.py`
- Create: `tests/extraction/test_formatter.py`
- Create: `tests/extraction/test_validator.py`

**Interfaces:**
- Consumes: `Span`, `IndexTriple`, `Entity`, `SurfaceTriple` (Task 4); `tokenize` (Task 4); `Ontology.entity_names`, `.canonical`, `.allowed` (Task 3)
- Produces:
  - `locate_spans(text: str, entities: Iterable[Entity], taken: Iterable[Span] = ()) -> list[Span]` (`text` is tokenized)
  - `resolve_triples(spans: Sequence[Span], triples: Iterable[SurfaceTriple]) -> list[IndexTriple]`
  - `token_offsets(sentence: str, tokens: Sequence[str]) -> list[tuple[int, int]]` (raises `ValueError` if a token is not found)
  - `validate(spans: Sequence[Span], triples: Iterable[IndexTriple], ontology: Ontology) -> tuple[list[Span], list[IndexTriple], list[str]]`. The triples come back in stored direction and refer to the returned span list. The `list[str]` is one human-readable reason per dropped item.

The DNRTI-only parts of the old `formatter.py` are not ported: `bio_tags`, `build_relations` (the `noRelation` matrix), `format_record` and `select`. The spec's output is entities with offsets plus relation triples. DNRTI records were the web app's dataset format.

- [ ] **Step 1: Write the failing tests**

`tests/extraction/test_formatter.py`:

```python
import pytest

from crawler.extraction.formatter import locate_spans, resolve_triples, token_offsets
from crawler.extraction.tokenizer import tokenize

TEXT = "The admin@338 has largely targeted organizations with PlugX ."


def test_locate_spans_finds_token_positions():
    spans = locate_spans(TEXT, [("admin@338", "ThreatGroup"), ("organizations", "Organization")])
    assert spans == [[1, 2, "admin@338", "ThreatGroup"], [5, 6, "organizations", "Organization"]]


def test_locate_spans_handles_multi_token_entities():
    spans = locate_spans("the Fancy Bear group", [("Fancy Bear", "ThreatGroup")])
    assert spans == [[1, 3, "Fancy Bear", "ThreatGroup"]]


def test_locate_spans_takes_next_unused_occurrence_for_repeats():
    spans = locate_spans("PlugX drops PlugX", [("PlugX", "Malware"), ("PlugX", "Malware")])
    assert spans == [[0, 1, "PlugX", "Malware"], [2, 3, "PlugX", "Malware"]]


def test_locate_spans_drops_entities_not_in_text():
    assert locate_spans(TEXT, [("Lazarus", "ThreatGroup")]) == []


def test_locate_spans_drops_overlaps_and_respects_taken():
    spans = locate_spans(
        "the Fancy Bear group",
        [("Fancy Bear", "ThreatGroup"), ("Bear", "ThreatGroup")],
    )
    assert spans == [[1, 3, "Fancy Bear", "ThreatGroup"]]
    assert locate_spans("uses PlugX", [("PlugX", "Tool")], taken=[[1, 2, "PlugX", "Malware"]]) == []


def test_locate_spans_tolerates_spacing_and_a_sentence_period():
    assert locate_spans("uses the  Fancy   Bear tool", [("Fancy Bear", "ThreatGroup")]) == [
        [2, 4, "Fancy Bear", "ThreatGroup"]
    ]
    assert locate_spans("it uses PlugX .", [("PlugX.", "Malware")]) == [[2, 3, "PlugX", "Malware"]]


def test_resolve_triples_maps_surfaces_to_span_indices():
    spans = [[0, 1, "APT28", "ThreatGroup"], [2, 3, "PlugX", "Malware"]]
    assert resolve_triples(spans, [("APT28", "uses", "PlugX"), ("APT28", "uses", "Nope")]) == [
        (0, "uses", 1)
    ]


@pytest.mark.parametrize(
    "sentence",
    [
        "APT28 used X-Agent.",
        'The “Sofacy” group’s  loader,\tX-Agent, hit (Germany)!',
        "  APT28's   implant contacted evil[.]com?  ",
        "Line one about APT28 and\r\nX-Agent: done.",
    ],
)
def test_token_offsets_slice_the_original_sentence(sentence):
    tokens = tokenize(sentence).split()
    offsets = token_offsets(sentence, tokens)

    assert [sentence[s:e] for s, e in offsets] == tokens
    assert all(a[1] <= b[0] for a, b in zip(offsets, offsets[1:], strict=False))


def test_token_offsets_rejects_tokens_not_in_the_sentence():
    with pytest.raises(ValueError, match="not found"):
        token_offsets("APT28 used X-Agent", ["APT28", "PlugX"])
```

`tests/extraction/test_validator.py`:

```python
from crawler.extraction.validator import validate

SPANS = [
    [0, 1, "APT28", "ThreatGroup"],
    [2, 3, "X-Agent", "Malware"],
    [5, 6, "banks", "Organization"],
    [7, 8, "Germany", "Location"],
]


def test_keeps_allowed_triples(ontology):
    spans, triples, dropped = validate(
        SPANS, [(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)], ontology
    )
    assert spans == SPANS
    assert triples == [(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)]
    assert dropped == []


def test_drops_triples_the_ontology_does_not_allow(ontology):
    _, triples, dropped = validate(SPANS, [(1, "targets", 2)], ontology)
    assert triples == []
    assert dropped == [
        "X-Agent targets banks: ontology does not allow Malware targets Organization"
    ]


def test_drops_unknown_relation_names(ontology):
    _, triples, dropped = validate(SPANS, [(0, "loves", 1)], ontology)
    assert triples == [] and dropped == ["loves: unknown relation"]


def test_turns_inverse_names_into_the_stored_direction(ontology):
    _, triples, _ = validate(SPANS, [(1, "used-by", 0)], ontology)
    assert triples == [(0, "uses", 1)]


def test_generic_relation_only_when_nothing_specific_fits(ontology):
    _, kept, dropped = validate(SPANS, [(0, "located-in", 3), (1, "located-in", 3)], ontology)
    assert kept == [(1, "located-in", 3)]
    assert "ThreatGroup located-in Location" in dropped[0]


def test_drops_unknown_entity_types_and_reindexes(ontology):
    spans = [[9, 10, "thing", "Gadget"], *SPANS]
    kept, triples, dropped = validate(spans, [(0, "uses", 2), (1, "operates-in", 4)], ontology)

    assert [s[2] for s in kept] == ["APT28", "X-Agent", "banks", "Germany"]
    assert triples == [(0, "operates-in", 3)]
    assert "thing: unknown entity type Gadget" in dropped


def test_drops_self_loops_and_duplicates(ontology):
    _, triples, _ = validate(SPANS, [(0, "uses", 0), (0, "uses", 1), (1, "used-by", 0)], ontology)
    assert triples == [(0, "uses", 1)]


def test_alias_between_groups_is_allowed_in_either_order(ontology):
    spans = [[0, 1, "APT28", "ThreatGroup"], [4, 6, "Fancy Bear", "ThreatGroup"]]
    _, triples, _ = validate(spans, [(1, "alias-of", 0)], ontology)
    assert triples == [(1, "alias-of", 0)]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/extraction/test_formatter.py tests/extraction/test_validator.py -v`
Expected: collection errors, `No module named 'crawler.extraction.formatter'` / `.validator`

- [ ] **Step 3: Implement**

`src/crawler/extraction/formatter.py`:

```python
"""Place extracted entity strings on tokens, and tokens on characters.

The LLM answers with entity *strings* and (source, relation, target) string triples;
everything positional is computed here.
"""

from collections.abc import Iterable, Iterator, Sequence

from crawler.extraction.spans import Entity, IndexTriple, Span, SurfaceTriple
from crawler.extraction.tokenizer import tokenize

PUNCT = set('.,;:!?"()[]{}')


def _entity_tokens(surface: str) -> list[str]:
    tokens = tokenize(surface, split_final_period=False).split()
    while tokens and tokens[-1] in PUNCT:
        tokens.pop()
    while tokens and tokens[0] in PUNCT:
        tokens.pop(0)
    return tokens


def _candidates(surface: str) -> Iterator[list[str]]:
    """The entity's tokens, then (for "PlugX.") the same without a trailing period."""
    tokens = _entity_tokens(surface)
    yield tokens
    if tokens and len(tokens[-1]) > 1 and tokens[-1].endswith("."):
        yield tokens[:-1] + [tokens[-1][:-1]]


def _find(
    tokens: Sequence[str], used: Sequence[bool], needle: Sequence[str]
) -> tuple[int, int] | None:
    for start in range(len(tokens) - len(needle) + 1):
        end = start + len(needle)
        if list(tokens[start:end]) == list(needle) and not any(used[start:end]):
            return start, end
    return None


def locate_spans(text: str, entities: Iterable[Entity], taken: Iterable[Span] = ()) -> list[Span]:
    """Map (surface, type) pairs to [start, end, surface, type] spans in tokenized `text`.

    Repeated strings take the next unused occurrence. Entities not found, or overlapping an
    already placed span or one in `taken`, are dropped.
    """
    tokens = text.split()
    used = [False] * len(tokens)
    for start, end, *_ in taken:
        used[start:end] = [True] * (end - start)
    spans: list[Span] = []
    for surface, label in entities:
        for needle in _candidates(surface):
            found = _find(tokens, used, needle) if needle else None
            if found:
                start, end = found
                used[start:end] = [True] * len(needle)
                spans.append([start, end, " ".join(needle), label])
                break
    return sorted(spans, key=lambda s: s[0])


def resolve_triples(spans: Sequence[Span], triples: Iterable[SurfaceTriple]) -> list[IndexTriple]:
    """Turn (source_text, relation, target_text) into span indices.

    A text refers to the first span with that surface. Triples naming a text that is not
    among the spans are dropped.
    """
    index: dict[str, int] = {}
    for n, span in enumerate(spans):
        index.setdefault(span[2], n)

    def lookup(surface: str) -> int | None:
        return next((index[k] for k in map(" ".join, _candidates(surface)) if k in index), None)

    resolved: list[IndexTriple] = []
    for subj, rel, obj in triples:
        s, o = lookup(subj), lookup(obj)
        if s is not None and o is not None:
            resolved.append((s, rel, o))
    return resolved


def token_offsets(sentence: str, tokens: Sequence[str]) -> list[tuple[int, int]]:
    """Character [start, end) of each token in `sentence`.

    tokenize() only inserts spaces, so every token is found, in order, by scanning forward
    from the end of the previous one.
    """
    out: list[tuple[int, int]] = []
    cursor = 0
    for token in tokens:
        start = sentence.find(token, cursor)
        if start < 0:
            raise ValueError(f"token {token!r} not found in sentence after offset {cursor}")
        end = start + len(token)
        out.append((start, end))
        cursor = end
    return out
```

`src/crawler/extraction/validator.py`:

```python
"""Enforce the ontology on merged rule + LLM output.

validate(spans, triples, ontology) -> (spans, triples, dropped)
Spans whose type the ontology lacks are removed and the survivors reindexed. Triples are
rewritten into the stored direction ("used-by" becomes "uses" with source and target swapped),
deduplicated, and kept only if the ontology allows (source type, relation, target type).
`dropped` explains every removal, for the output file's audit trail.
"""

from collections.abc import Iterable, Sequence

from crawler.extraction.ontology import Ontology
from crawler.extraction.spans import IndexTriple, Span


def validate(
    spans: Sequence[Span], triples: Iterable[IndexTriple], ontology: Ontology
) -> tuple[list[Span], list[IndexTriple], list[str]]:
    known = set(ontology.entity_names)
    dropped: list[str] = []

    kept: list[Span] = []
    new_index: dict[int, int] = {}
    for n, span in enumerate(spans):
        if span[3] in known:
            new_index[n] = len(kept)
            kept.append(span)
        else:
            dropped.append(f"{span[2]}: unknown entity type {span[3]}")

    out: list[IndexTriple] = []
    seen: set[IndexTriple] = set()
    for src, relation, tgt in triples:
        if src not in new_index or tgt not in new_index or src == tgt:
            continue
        src, tgt = new_index[src], new_index[tgt]
        name, flipped = ontology.canonical(relation)
        if name is None:
            dropped.append(f"{relation}: unknown relation")
            continue
        if flipped:
            src, tgt = tgt, src
        s_type, t_type = kept[src][3], kept[tgt][3]
        if not ontology.allowed(s_type, name, t_type):
            dropped.append(
                f"{kept[src][2]} {name} {kept[tgt][2]}: "
                f"ontology does not allow {s_type} {name} {t_type}"
            )
            continue
        triple = (src, name, tgt)
        if triple not in seen:
            seen.add(triple)
            out.append(triple)
    return kept, out, dropped
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/extraction -v`
Expected: all PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add src/crawler/extraction tests/extraction
git commit -m "feat: span placement, character offsets and ontology validator

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Ontology-driven prompt, strict response schema, and reply parser

**Files:**
- Create: `src/crawler/extraction/llm.py`
- Create: `src/crawler/extraction/resources/extract.txt`
- Create: `src/crawler/extraction/resources/examples.json` (copied)
- Create: `tests/extraction/test_llm.py`

**Interfaces:**
- Consumes: `Ontology` (Task 3); `Span`, `Entity`, `SurfaceTriple` (Task 4)
- Produces:
  - `Complete = Callable[[str, dict[str, Any]], Awaitable[str]]` (prompt, JSON schema → raw reply)
  - `load_examples(path: Path = EXAMPLES_PATH) -> list[dict[str, Any]]`
  - `build_prompt(sentence: str, ontology: Ontology, known: Sequence[Span] = (), examples: Sequence[dict[str, Any]] | None = None) -> str`
  - `response_schema(ontology: Ontology) -> dict[str, Any]`
  - `parse_response(raw: str, ontology: Ontology, known: Sequence[Span] = ()) -> tuple[list[Entity], list[SurfaceTriple]]` (raises `ValueError` on a malformed reply)
  - `class LLMExtractor(complete: Complete, ontology: Ontology, examples=None, attempts: int = 2)` with `async extract(sentence: str, known: Sequence[Span] = ()) -> tuple[list[Entity], list[SurfaceTriple]]` (raises `ValueError` after `attempts` unusable replies), property `model_name -> str | None`, attribute `schema`

**How the schema enforces the ontology:**
- `entities[].type` is an `enum` of the 15 names.
- Each `relations[]` item must match one `anyOf` branch. There is one branch per (stored relation, source type). The branch pins `relation` and `source_type` to one-value enums and lists the allowed `target_type`s.
- The provider therefore cannot decode a triple whose types the ontology forbids. All objects use `additionalProperties: false` and list every property as required, which is what strict mode demands.
- Only stored relation names are offered; inverse names are not.
- What JSON Schema cannot express is cross-referenced in `parse_response`: whether `source` is actually an entity of type `source_type`.

- [ ] **Step 1: Copy the examples, write the prompt template**

```bash
cp ../text-extractor/prompts/examples_v2.json src/crawler/extraction/resources/examples.json
```

`src/crawler/extraction/resources/extract.txt`:

```text
You extract cyber threat intelligence entities and relations from one sentence.

ENTITY TYPES (use only these)
{entity_types}

RELATIONS (use only these names, only in the direction shown: source type -> target type)
{relations}

RULES
- Copy each entity's text exactly as it appears in the sentence, keeping spaces around punctuation as written.
- Keep entities short: the minimal phrase that names the thing ("PlugX", not "the new PlugX variant").
- Only output relations the sentence states or clearly implies. Source and target must be entity texts from your list or from the already-found list, and source_type and target_type must be the types those entities have.
- located-in and occurs-at are only for entities that have no more specific relation to a location or a time.
- If nothing in the sentence fits these types, return empty lists. Never invent a type or a relation that is not listed.

ALREADY FOUND (do not list these again as entities, but use them in relations)
{known}

EXAMPLES
{examples}

SENTENCE
{sentence}
```

- [ ] **Step 2: Write the failing tests** — `tests/extraction/test_llm.py`

```python
import json

import pytest

from crawler.extraction.llm import (
    LLMExtractor,
    build_prompt,
    load_examples,
    parse_response,
    response_schema,
)


def reply(entities=(), relations=()) -> str:
    return json.dumps(
        {
            "entities": [{"text": t, "type": ty} for t, ty in entities],
            "relations": [
                {"source": s, "source_type": st, "relation": r, "target": t, "target_type": tt}
                for s, st, r, t, tt in relations
            ],
        }
    )


def objects(node):
    """Every JSON-Schema object node in `node`."""
    if isinstance(node, dict):
        if node.get("type") == "object":
            yield node
        for value in node.values():
            yield from objects(value)
    elif isinstance(node, list):
        for value in node:
            yield from objects(value)


def test_schema_entity_types_are_exactly_the_ontology(ontology):
    schema = response_schema(ontology)
    entity = schema["properties"]["entities"]["items"]
    assert entity["properties"]["type"]["enum"] == list(ontology.entity_names)


def test_schema_relations_cover_exactly_the_allowed_triples(ontology):
    offered = set()
    for branch in response_schema(ontology)["properties"]["relations"]["items"]["anyOf"]:
        p = branch["properties"]
        for relation in p["relation"]["enum"]:
            for source in p["source_type"]["enum"]:
                for target in p["target_type"]["enum"]:
                    offered.add((source, relation, target))

    expected = {(s, r, t) for r, pairs in ontology.allowed_pairs.items() for s, t in pairs}
    assert offered == expected


def test_schema_meets_strict_structured_output_rules(ontology):
    for node in objects(response_schema(ontology)):
        assert node["additionalProperties"] is False
        assert sorted(node["required"]) == sorted(node["properties"])


def test_prompt_describes_the_ontology_and_the_sentence(ontology):
    prompt = build_prompt(
        "APT28 used X-Agent .", ontology, known=[[0, 1, "APT28", "ThreatGroup"]], examples=[]
    )
    for name in ontology.entity_names:
        assert f"- {name}: " in prompt
    assert "- uses: ThreatActor -> Malware" in prompt
    assert "- sub_technique_of: " in prompt
    assert '- "APT28" (ThreatGroup)' in prompt
    assert prompt.rstrip().endswith("APT28 used X-Agent .")


def test_shipped_examples_only_teach_allowed_relations(ontology):
    examples = load_examples()
    assert examples
    for example in examples:
        types = {e["text"]: e["type"] for e in example["entities"]}
        for r in example["relations"]:
            pair = (types[r["source"]], types[r["target"]])
            assert pair in ontology.allowed_pairs[r["relation"]], r
    prompt = build_prompt("x", ontology)
    assert '"source_type": "ThreatGroup"' in prompt


def test_parse_keeps_valid_entities_and_relations(ontology):
    raw = reply(
        [("APT28", "ThreatGroup"), ("X-Agent", "Malware")],
        [("APT28", "ThreatGroup", "uses", "X-Agent", "Malware")],
    )
    assert parse_response(raw, ontology) == (
        [("APT28", "ThreatGroup"), ("X-Agent", "Malware")],
        [("APT28", "uses", "X-Agent")],
    )


def test_parse_drops_relation_whose_end_is_not_an_entity(ontology):
    raw = reply([("APT28", "ThreatGroup")], [("APT28", "ThreatGroup", "uses", "PlugX", "Malware")])
    assert parse_response(raw, ontology)[1] == []


def test_parse_drops_relation_with_wrong_claimed_type(ontology):
    raw = reply(
        [("APT28", "ThreatGroup"), ("X-Agent", "Malware")],
        [("APT28", "ThreatGroup", "uses", "X-Agent", "Tool")],
    )
    assert parse_response(raw, ontology)[1] == []


def test_parse_drops_triples_the_ontology_forbids(ontology):
    raw = reply(
        [("X-Agent", "Malware"), ("banks", "Organization")],
        [("X-Agent", "Malware", "targets", "banks", "Organization")],
    )
    assert parse_response(raw, ontology)[1] == []


def test_parse_drops_unknown_types_and_blank_text(ontology):
    raw = reply([("thing", "Gadget"), ("  ", "Malware"), ("PlugX", "Malware")])
    assert parse_response(raw, ontology)[0] == [("PlugX", "Malware")]


def test_parse_lets_relations_use_already_found_spans(ontology):
    raw = reply([("X-Agent", "Malware")], [("APT28", "ThreatGroup", "uses", "X-Agent", "Malware")])
    known = [[0, 1, "APT28", "ThreatGroup"]]
    assert parse_response(raw, ontology, known)[1] == [("APT28", "uses", "X-Agent")]


@pytest.mark.parametrize(
    "raw", ["not json", "[]", '{"entities": []}', '{"entities": [1], "relations": []}']
)
def test_parse_rejects_malformed_replies(ontology, raw):
    with pytest.raises(ValueError, match="unusable reply"):
        parse_response(raw, ontology)


class ScriptedComplete:
    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, dict]] = []
        self.last_model = "model-a"

    async def __call__(self, prompt: str, schema: dict) -> str:
        self.calls.append((prompt, schema))
        return self.replies.pop(0)


async def test_extractor_sends_the_prompt_and_the_strict_schema(ontology):
    complete = ScriptedComplete(reply([("PlugX", "Malware")]))
    extractor = LLMExtractor(complete, ontology, examples=[])

    assert await extractor.extract("it used PlugX .") == ([("PlugX", "Malware")], [])
    prompt, schema = complete.calls[0]
    assert "it used PlugX ." in prompt
    assert schema == response_schema(ontology)
    assert extractor.model_name == "model-a"


async def test_extractor_retries_once_on_an_unusable_reply(ontology):
    complete = ScriptedComplete("garbage", reply([("PlugX", "Malware")]))
    extractor = LLMExtractor(complete, ontology, examples=[])

    assert await extractor.extract("it used PlugX .") == ([("PlugX", "Malware")], [])
    assert len(complete.calls) == 2


async def test_extractor_raises_after_repeated_unusable_replies(ontology):
    extractor = LLMExtractor(ScriptedComplete("garbage", "worse"), ontology, examples=[])
    with pytest.raises(ValueError, match="no usable reply after 2 attempts"):
        await extractor.extract("it used PlugX .")
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/extraction/test_llm.py -v`
Expected: collection error, `No module named 'crawler.extraction.llm'`

- [ ] **Step 4: Implement** — `src/crawler/extraction/llm.py`

```python
"""Schema-constrained LLM pass.

The ontology becomes two things: a prompt that describes it, and a JSON Schema that the
provider enforces while decoding (structured outputs). The schema enumerates entity types
and, for relations, one branch per (relation, source type) listing the permitted target
types, so a triple the ontology lacks cannot be produced. parse_response still checks every
reply: the schema cannot know which *strings* are entities of which type.
"""

import json
from collections.abc import Awaitable, Callable, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from crawler.extraction.ontology import Ontology
from crawler.extraction.spans import Entity, Span, SurfaceTriple

RESOURCES = Path(__file__).resolve().parent / "resources"
PROMPT_PATH = RESOURCES / "extract.txt"
EXAMPLES_PATH = RESOURCES / "examples.json"

# complete(prompt, json_schema) -> the model's raw JSON reply
Complete = Callable[[str, dict[str, Any]], Awaitable[str]]


def load_examples(path: Path = EXAMPLES_PATH) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _template() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _shot(example: dict[str, Any], ontology: Ontology) -> str | None:
    """One few-shot example in the reply format, keeping only what the ontology allows."""
    names = set(ontology.entity_names)
    types = {e["text"]: e["type"] for e in example["entities"] if e["type"] in names}
    if not types:
        return None
    relations = [
        {
            "source": r["source"],
            "source_type": types[r["source"]],
            "relation": r["relation"],
            "target": r["target"],
            "target_type": types[r["target"]],
        }
        for r in example["relations"]
        if r["source"] in types
        and r["target"] in types
        and (types[r["source"]], types[r["target"]])
        in ontology.allowed_pairs.get(r["relation"], ())
    ]
    output = {
        "entities": [{"text": t, "type": ty} for t, ty in types.items()],
        "relations": relations,
    }
    return f"Sentence: {example['text']}\nOutput: {json.dumps(output, ensure_ascii=False)}"


def build_prompt(
    sentence: str,
    ontology: Ontology,
    known: Sequence[Span] = (),
    examples: Sequence[dict[str, Any]] | None = None,
) -> str:
    if examples is None:
        examples = load_examples()
    type_lines = "\n".join(f"- {t.name}: {t.description}" for t in ontology.entity_types)
    descriptions = {r.name: r.description for r in ontology.relations}
    relation_lines = "\n".join(
        f"- {name}: {', '.join(f'{s} -> {t}' for s, t in pairs)}  ({descriptions[name]})"
        for name, pairs in ontology.allowed_pairs.items()
        if pairs
    )
    known_lines = "\n".join(f'- "{s[2]}" ({s[3]})' for s in known) or "(none)"
    shots = [shot for example in examples if (shot := _shot(example, ontology))]

    prompt = _template()
    for key, value in (
        ("{entity_types}", type_lines),
        ("{relations}", relation_lines),
        ("{known}", known_lines),
        ("{examples}", "\n\n".join(shots) or "(none)"),
        ("{sentence}", sentence),
    ):
        prompt = prompt.replace(key, value)
    return prompt


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def response_schema(ontology: Ontology) -> dict[str, Any]:
    branches: list[dict[str, Any]] = []
    for relation, pairs in ontology.allowed_pairs.items():
        targets_by_source: dict[str, list[str]] = {}
        for source_type, target_type in pairs:
            targets_by_source.setdefault(source_type, []).append(target_type)
        for source_type, targets in targets_by_source.items():
            branches.append(
                _object(
                    {
                        "source": {"type": "string"},
                        "source_type": {"type": "string", "enum": [source_type]},
                        "relation": {"type": "string", "enum": [relation]},
                        "target": {"type": "string"},
                        "target_type": {"type": "string", "enum": targets},
                    }
                )
            )

    entity = _object(
        {
            "text": {"type": "string"},
            "type": {"type": "string", "enum": list(ontology.entity_names)},
        }
    )
    return _object(
        {
            "entities": {"type": "array", "items": entity},
            "relations": {"type": "array", "items": {"anyOf": branches}},
        }
    )


def parse_response(
    raw: str, ontology: Ontology, known: Sequence[Span] = ()
) -> tuple[list[Entity], list[SurfaceTriple]]:
    """Read a structured reply. Raises ValueError if it is not the expected shape.

    Entities of unknown types are dropped. A relation survives only if the ontology allows
    it and both its ends are entities, new or already found, of exactly the types it claims.
    """
    try:
        data = json.loads(raw)
        entities = [(str(e["text"]), str(e["type"])) for e in data["entities"]]
        relations = [
            (
                str(r["source"]),
                str(r["source_type"]),
                str(r["relation"]),
                str(r["target"]),
                str(r["target_type"]),
            )
            for r in data["relations"]
        ]
    except (json.JSONDecodeError, KeyError, TypeError) as err:
        raise ValueError(f"unusable reply: {err}") from err

    names = set(ontology.entity_names)
    entities = [(text, type_) for text, type_ in entities if type_ in names and text.strip()]
    typed = {(s[2], s[3]) for s in known} | set(entities)
    triples = [
        (src, rel, tgt)
        for src, src_type, rel, tgt, tgt_type in relations
        if (src_type, tgt_type) in ontology.allowed_pairs.get(rel, ())
        and (src, src_type) in typed
        and (tgt, tgt_type) in typed
    ]
    return entities, triples


class LLMExtractor:
    """One tokenized sentence in; new entities and relation triples out, held to the ontology."""

    def __init__(
        self,
        complete: Complete,
        ontology: Ontology,
        examples: Sequence[dict[str, Any]] | None = None,
        attempts: int = 2,
    ) -> None:
        self.complete = complete
        self.ontology = ontology
        self.examples = load_examples() if examples is None else list(examples)
        self.schema = response_schema(ontology)
        self.attempts = attempts

    @property
    def model_name(self) -> str | None:
        return getattr(self.complete, "last_model", None)

    async def extract(
        self, sentence: str, known: Sequence[Span] = ()
    ) -> tuple[list[Entity], list[SurfaceTriple]]:
        prompt = build_prompt(sentence, self.ontology, known, self.examples)
        error: ValueError | None = None
        for _ in range(self.attempts):
            raw = await self.complete(prompt, self.schema)
            try:
                return parse_response(raw, self.ontology, known)
            except ValueError as exc:
                error = exc
        raise ValueError(f"no usable reply after {self.attempts} attempts: {error}")
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/extraction/test_llm.py -v`
Expected: all PASS

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add src/crawler/extraction tests/extraction/test_llm.py
git commit -m "feat: ontology-generated prompt and strict structured-output schema

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Async LLM client through the crawler's rate limiter

**Files:**
- Create: `src/crawler/extraction/client.py`
- Create: `tests/extraction/test_llm_client.py`
- Modify: `src/crawler/config.py` (LLM settings)
- Modify: `.env.example`

**Interfaces:**
- Consumes: `DomainRateLimiter.acquire(url)` (duck-typed: any object with `async acquire(url)`); `Settings`
- Produces:
  - `PROVIDERS: dict[str, str]` (provider → chat-completions URL)
  - `class LLMError(RuntimeError)`
  - `response_format(schema: dict) -> dict`
  - `class ChatClient(url, api_key, models, client, limiter, gate, retries=2, sleep=None)`; `async __call__(prompt: str, schema: dict) -> str` (matches `Complete`); public attrs `url: str`, `models: list[str]`, `last_model: str | None`
  - `model_list(primary: str, fallbacks: str) -> list[str]`
  - `build_chat_client(settings: Settings, client: httpx.AsyncClient, limiter, gate: asyncio.Semaphore) -> ChatClient` (raises `LLMError` when the provider's key is unset)
  - `Settings`: `llm_provider: Literal["mistral","gemini","grok"] = "mistral"`, `llm_parallel: int = 4`, `llm_requests_per_minute: int = 30`, `llm_timeout: float = 120.0`, and `{mistral,gemini,grok}_api_key: str | None`, `_model: str`, `_fallback_models: str`

**One client, three providers:**
- Mistral, xAI Grok, and Gemini (through its OpenAI-compatibility endpoint) all accept `response_format: {"type": "json_schema", "json_schema": {..., "strict": true}}`.
- This replaces the extractor's three provider modules and its `google-genai` dependency.
- Mistral now gets a schema too. The old extractor sent it plain JSON mode, which the spec's Objective 3.4 does not allow.

- [ ] **Step 1: Write the failing tests** — `tests/extraction/test_llm_client.py`

```python
import asyncio
import json

import httpx
import pytest

from crawler.config import Settings
from crawler.extraction.client import PROVIDERS, ChatClient, LLMError, build_chat_client

URL = "https://llm.example/v1/chat/completions"


class RecordingLimiter:
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def acquire(self, url: str) -> None:
        self.urls.append(url)


def ok(content: str = '{"entities": [], "relations": []}') -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def make(handler, models=("m1",), gate=None, limiter=None, sleeps=None) -> ChatClient:
    async def sleep(seconds: float) -> None:
        if sleeps is not None:
            sleeps.append(seconds)

    return ChatClient(
        URL,
        "secret",
        list(models),
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limiter or RecordingLimiter(),
        gate or asyncio.Semaphore(4),
        sleep=sleep,
    )


async def test_sends_a_strict_json_schema_and_returns_the_content():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return ok("REPLY")

    chat = make(handler)
    assert await chat("the prompt", {"type": "object"}) == "REPLY"

    body = json.loads(seen[0].content)
    assert body["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "cti_extraction", "schema": {"type": "object"}, "strict": True},
    }
    assert body["model"] == "m1" and body["temperature"] == 0
    assert body["messages"] == [{"role": "user", "content": "the prompt"}]
    assert seen[0].headers["authorization"] == "Bearer secret"
    assert chat.last_model == "m1"


async def test_every_attempt_passes_the_rate_limiter():
    replies = iter([httpx.Response(429), ok()])
    limiter = RecordingLimiter()
    chat = make(lambda request: next(replies), limiter=limiter)

    await chat("p", {})

    assert limiter.urls == [URL, URL]


async def test_rate_limits_and_server_errors_are_retried_with_backoff():
    replies = iter([httpx.Response(429), httpx.Response(503), ok("fine")])
    sleeps: list[float] = []
    chat = make(lambda request: next(replies), sleeps=sleeps)

    assert await chat("p", {}) == "fine"
    assert sleeps == [2, 4]


async def test_client_errors_are_not_retried():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(400, text="schema not supported")

    with pytest.raises(LLMError, match="HTTP 400: schema not supported"):
        await make(handler)("p", {})
    assert len(calls) == 1


async def test_model_without_allowance_falls_back_to_the_next():
    def handler(request):
        if json.loads(request.content)["model"] == "m1":
            return httpx.Response(429, headers={"x-ratelimit-limit-req-minute": "0"})
        return ok("from m2")

    chat = make(handler, models=("m1", "m2"))

    assert await chat("p", {}) == "from m2"
    assert chat.last_model == "m2"


async def test_gives_up_after_the_retries():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503)

    with pytest.raises(LLMError, match="HTTP 503"):
        await make(handler)("p", {})
    assert len(calls) == 3


async def test_network_errors_are_retried_then_reported():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(LLMError, match="ConnectError"):
        await make(handler)("p", {})


async def test_unexpected_response_shape_is_an_llm_error():
    with pytest.raises(LLMError, match="unexpected response shape"):
        await make(lambda request: httpx.Response(200, json={"oops": 1}))("p", {})


async def test_the_semaphore_bounds_requests_in_flight():
    in_flight = peak = 0

    async def handler(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return ok()

    chat = make(handler, gate=asyncio.Semaphore(2))
    await asyncio.gather(*(chat("p", {}) for _ in range(6)))

    assert peak == 2


def settings(**values) -> Settings:
    return Settings(_env_file=None, database_url="postgresql+psycopg://x@y/z", **values)


def test_build_chat_client_needs_the_providers_key():
    with pytest.raises(LLMError, match="GROK_API_KEY"):
        build_chat_client(
            settings(llm_provider="grok", grok_api_key=None),
            httpx.AsyncClient(),
            RecordingLimiter(),
            asyncio.Semaphore(1),
        )


def test_build_chat_client_uses_the_provider_url_and_fallbacks():
    chat = build_chat_client(
        settings(
            llm_provider="gemini",
            gemini_api_key="k",
            gemini_model="a",
            gemini_fallback_models="b, c,",
        ),
        httpx.AsyncClient(),
        RecordingLimiter(),
        asyncio.Semaphore(1),
    )
    assert chat.url == PROVIDERS["gemini"]
    assert chat.models == ["a", "b", "c"]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/extraction/test_llm_client.py -v`
Expected: collection error, `No module named 'crawler.extraction.client'`

- [ ] **Step 3: Implement**

In `src/crawler/config.py`, add `from typing import Literal` to the imports and append to `Settings`:

```python
    # LLM extraction (`crawler extract`). Keys belong in .env; see .env.example.
    llm_provider: Literal["mistral", "gemini", "grok"] = "mistral"
    llm_parallel: int = 4  # requests in flight at once
    llm_requests_per_minute: int = 30
    llm_timeout: float = 120.0
    mistral_api_key: str | None = None
    mistral_model: str = "ministral-14b-latest"
    mistral_fallback_models: str = "ministral-8b-latest"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.8-flash"
    gemini_fallback_models: str = ""
    grok_api_key: str | None = None
    grok_model: str = "grok-4-fast-non-reasoning"
    grok_fallback_models: str = ""
```

`src/crawler/extraction/client.py`:

```python
"""Async client for OpenAI-compatible chat-completion APIs with structured outputs.

Mistral, Gemini (through its OpenAI compatibility endpoint) and xAI Grok all accept a strict
`json_schema` response format, so one client serves all three. Every request waits on a
shared semaphore and then on a DomainRateLimiter: the same controls that keep the crawler
polite to publishers keep extraction inside API quotas.
"""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Protocol

import httpx

from crawler.config import Settings

PROVIDERS: dict[str, str] = {
    "mistral": "https://api.mistral.ai/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "grok": "https://api.x.ai/v1/chat/completions",
}
RETRY_STATUS = frozenset({429, 500, 502, 503})
SCHEMA_NAME = "cti_extraction"


class LLMError(RuntimeError):
    """The provider did not produce a usable reply."""


class Limiter(Protocol):
    async def acquire(self, url: str) -> None: ...


def response_format(schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {"name": SCHEMA_NAME, "schema": schema, "strict": True},
    }


class ChatClient:
    """complete(prompt, schema) for one provider, trying each model in order.

    429 and 5xx are retried with backoff; any other error status is raised at once, since
    retrying a rejected key or schema only spends quota. A model the account has no
    allowance for (limit 0 requests/minute) is skipped for the rest of the run.
    `last_model` names the model that answered most recently.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        models: Sequence[str],
        client: httpx.AsyncClient,
        limiter: Limiter,
        gate: asyncio.Semaphore,
        retries: int = 2,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        if not models:
            raise ValueError("at least one model is required")
        self.url = url
        self.models = list(models)
        self.last_model: str | None = None
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._client = client
        self._limiter = limiter
        self._gate = gate
        self._retries = retries
        self._sleep = sleep or asyncio.sleep
        self._unavailable: set[str] = set()

    async def __call__(self, prompt: str, schema: dict[str, Any]) -> str:
        last_error: LLMError | None = None
        for model in self.models:
            if model in self._unavailable:
                continue
            body = {
                "model": model,
                "temperature": 0,
                "response_format": response_format(schema),
                "messages": [{"role": "user", "content": prompt}],
            }
            for attempt in range(self._retries + 1):
                try:
                    response = await self._post(body)
                except httpx.HTTPError as exc:
                    last_error = LLMError(f"{model}: {type(exc).__name__}: {exc}")
                else:
                    if response.status_code == 200:
                        self.last_model = model
                        return _content(response, model)
                    last_error = LLMError(
                        f"{model}: HTTP {response.status_code}: {response.text[:300]}"
                    )
                    if response.status_code not in RETRY_STATUS:
                        raise last_error
                    if response.headers.get("x-ratelimit-limit-req-minute") == "0":
                        self._unavailable.add(model)
                        break
                if attempt < self._retries:
                    await self._sleep(2**attempt * 2)
        raise last_error or LLMError(f"no usable model among: {', '.join(self.models)}")

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        async with self._gate:
            await self._limiter.acquire(self.url)
            return await self._client.post(self.url, headers=self._headers, json=body)


def _content(response: httpx.Response, model: str) -> str:
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"{model}: unexpected response shape ({exc!r})") from exc
    if not isinstance(content, str):
        raise LLMError(f"{model}: reply content is not text")
    return content


def model_list(primary: str, fallbacks: str) -> list[str]:
    return [primary, *(m.strip() for m in fallbacks.split(",") if m.strip())]


def build_chat_client(
    settings: Settings,
    client: httpx.AsyncClient,
    limiter: Limiter,
    gate: asyncio.Semaphore,
) -> ChatClient:
    provider = settings.llm_provider
    key = getattr(settings, f"{provider}_api_key")
    if not key:
        raise LLMError(
            f"{provider.upper()}_API_KEY is not set; add it to .env or run with --rules-only"
        )
    models = model_list(
        getattr(settings, f"{provider}_model"), getattr(settings, f"{provider}_fallback_models")
    )
    return ChatClient(PROVIDERS[provider], key, models, client, limiter, gate)
```

Append to `.env.example`:

```bash

# LLM extraction (`crawler extract`). Fill in the key for the provider you pick.
# Provider: mistral, gemini or grok. All three are sent a strict JSON schema.
LLM_PROVIDER=mistral
# Requests in flight at once, and the per-minute ceiling for the provider's host.
LLM_PARALLEL=4
LLM_REQUESTS_PER_MINUTE=30

MISTRAL_API_KEY=
MISTRAL_MODEL=ministral-14b-latest
MISTRAL_FALLBACK_MODELS=ministral-8b-latest

GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODELS=

GROK_API_KEY=
GROK_MODEL=grok-4-fast-non-reasoning
GROK_FALLBACK_MODELS=
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/extraction/test_llm_client.py tests/test_config.py -v`
Expected: all PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add src/crawler/extraction/client.py src/crawler/config.py .env.example tests/extraction/test_llm_client.py
git commit -m "feat: async structured-output LLM client behind the crawler's rate limiter

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Document extraction pipeline (rules → LLM → validate → offsets)

**Files:**
- Create: `src/crawler/extraction/pipeline.py`
- Create: `tests/extraction/test_extract_pipeline.py`

**Interfaces:**
- Consumes: `split_sentences`, `tokenize` (Task 4); `RuleMatcher.find` (Task 4); `locate_spans`, `resolve_triples`, `token_offsets` (Task 5); `validate` (Task 5); `Ontology` (Task 3)
- Produces:
  - `class SentenceExtractor(Protocol)`: `async extract(sentence: str, known: Sequence[Span] = ()) -> tuple[list[Entity], list[SurfaceTriple]]` (`LLMExtractor` satisfies it)
  - `EntityMention(id: int, text: str, type: str, start: int, end: int, sentence: int, origin: Literal["rules","llm"])`. `start` and `end` are character offsets into the document text, and `text == document[start:end]`.
  - `RelationTriple(source: int, relation: str, target: int, sentence: int)`. `source` and `target` are `EntityMention.id`s, and the relation is in stored direction.
  - `DocumentExtraction(entities: tuple[EntityMention, ...], relations: tuple[RelationTriple, ...], sentences: int, llm_failures: int, warnings: tuple[str, ...] = (), dropped: tuple[str, ...] = ())`
  - `async extract_text(text: str, matcher: RuleMatcher, ontology: Ontology, llm: SentenceExtractor | None = None) -> DocumentExtraction`

Concurrency: all of a document's sentences are submitted together with `asyncio.gather`. The `ChatClient` semaphore (Task 7) bounds how many requests are actually in flight.

- [ ] **Step 1: Write the failing tests** — `tests/extraction/test_extract_pipeline.py`

```python
import pytest

from crawler.extraction.pipeline import DocumentExtraction, RelationTriple, extract_text
from crawler.extraction.rules import RuleMatcher

MATCHER = RuleMatcher(
    [
        {"name": "APT28", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
        {"name": "Fancy Bear", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
        {"name": "X-Agent", "type": "Malware", "id": "S0161", "case_sensitive": True},
        {"name": "Germany", "type": "Location", "id": "DE", "case_sensitive": True},
    ]
)


class FakeLLM:
    def __init__(self, answers=None, fail_on: str | None = None) -> None:
        self.answers = answers or {}
        self.fail_on = fail_on
        self.calls: list[tuple[str, list[str]]] = []

    async def extract(self, sentence, known=()):
        self.calls.append((sentence, [k[2] for k in known]))
        if self.fail_on and self.fail_on in sentence:
            raise RuntimeError("quota exceeded")
        for needle, answer in self.answers.items():
            if needle in sentence:
                return answer
        return [], []


def named(result, relation: RelationTriple) -> tuple[str, str, str]:
    return (
        result.entities[relation.source].text,
        relation.relation,
        result.entities[relation.target].text,
    )


async def test_rules_only_entities_carry_exact_character_offsets(ontology):
    text = "APT28, also known as Fancy Bear, used X-Agent.\n\nIt was seen in Germany in March 2019."

    result = await extract_text(text, MATCHER, ontology)

    assert [(e.text, e.type, e.sentence, e.origin) for e in result.entities] == [
        ("APT28", "ThreatGroup", 0, "rules"),
        ("Fancy Bear", "ThreatGroup", 0, "rules"),
        ("X-Agent", "Malware", 0, "rules"),
        ("Germany", "Location", 1, "rules"),
        ("March 2019", "Time", 1, "rules"),
    ]
    assert all(text[e.start : e.end] == e.text for e in result.entities)
    assert result.relations == (RelationTriple(0, "alias-of", 1, 0),)
    assert (result.sentences, result.llm_failures) == (2, 0)


async def test_llm_entities_and_relations_are_merged(ontology):
    text = "APT28 used X-Agent against NATO."
    llm = FakeLLM(
        {"NATO": ([("NATO", "Organization")], [("APT28", "targets", "NATO"), ("APT28", "uses", "X-Agent")])}
    )

    result = await extract_text(text, MATCHER, ontology, llm)

    nato = next(e for e in result.entities if e.text == "NATO")
    assert (nato.type, nato.origin, text[nato.start : nato.end]) == ("Organization", "llm", "NATO")
    assert {named(result, r) for r in result.relations} == {
        ("APT28", "targets", "NATO"),
        ("APT28", "uses", "X-Agent"),
    }
    assert llm.calls == [("APT28 used X-Agent against NATO .", ["APT28", "X-Agent"])]


async def test_llm_cannot_relabel_a_rule_span(ontology):
    llm = FakeLLM({"X-Agent": ([("X-Agent", "Tool")], [])})
    result = await extract_text("APT28 used X-Agent.", MATCHER, ontology, llm)
    assert [(e.text, e.type) for e in result.entities] == [
        ("APT28", "ThreatGroup"),
        ("X-Agent", "Malware"),
    ]


async def test_relations_the_ontology_forbids_are_dropped_and_recorded(ontology):
    llm = FakeLLM({"NATO": ([("NATO", "Organization")], [("X-Agent", "targets", "NATO")])})

    result = await extract_text("APT28 used X-Agent against NATO.", MATCHER, ontology, llm)

    assert result.relations == ()
    assert any("does not allow Malware targets Organization" in d for d in result.dropped)


async def test_llm_failure_keeps_rules_and_is_reported(ontology):
    llm = FakeLLM(fail_on="Germany")

    result = await extract_text("APT28 used X-Agent. They hit Germany.", MATCHER, ontology, llm)

    assert result.llm_failures == 1
    assert result.warnings == (
        "sentence 1: LLM failed (RuntimeError: quota exceeded); rules only",
    )
    assert "Germany" in {e.text for e in result.entities}


@pytest.mark.parametrize(
    "text",
    [
        "The “Sofacy” group’s  loader,\tX-Agent, hit Germany.",
        "  APT28's   implant (X-Agent) contacted evil[.]com!  ",
        "Line one about APT28.\r\nLine two: X-Agent in Germany?",
        "APT28 — also Fancy Bear — used X-Agent… again in 2019.",
    ],
)
async def test_offsets_survive_quotes_possessives_and_whitespace(ontology, text):
    result = await extract_text(text, MATCHER, ontology)

    assert result.entities
    for e in result.entities:
        assert text[e.start : e.end] == e.text


async def test_relation_ids_are_global_across_sentences(ontology):
    llm = FakeLLM({"Germany": ([], [("APT28", "operates-in", "Germany")])})

    result = await extract_text("X-Agent spread. APT28 hit Germany.", MATCHER, ontology, llm)

    [relation] = result.relations
    assert named(result, relation) == ("APT28", "operates-in", "Germany")
    assert relation.sentence == 1
    assert [e.id for e in result.entities] == [0, 1, 2]


async def test_empty_text_yields_nothing(ontology):
    assert await extract_text("   \n ", MATCHER, ontology, FakeLLM()) == DocumentExtraction(
        (), (), 0, 0
    )
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/extraction/test_extract_pipeline.py -v`
Expected: collection error, `No module named 'crawler.extraction.pipeline'`

- [ ] **Step 3: Implement** — `src/crawler/extraction/pipeline.py`

```python
"""Document text in, ontology-checked entities and relations out.

Per sentence: tokenize, run the rules, then ask the LLM for what the rules did not find.
Rule spans win any overlap, so the LLM can add entities but never relabel a regex or
dictionary hit. The merged result goes through the validator, and survivors are mapped back
to character offsets in the original text.
"""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from crawler.extraction.formatter import locate_spans, resolve_triples, token_offsets
from crawler.extraction.ontology import Ontology
from crawler.extraction.rules import RuleMatcher
from crawler.extraction.spans import Entity, IndexTriple, Span, SurfaceTriple
from crawler.extraction.tokenizer import split_sentences, tokenize
from crawler.extraction.validator import validate


class SentenceExtractor(Protocol):
    async def extract(
        self, sentence: str, known: Sequence[Span] = ()
    ) -> tuple[list[Entity], list[SurfaceTriple]]: ...


@dataclass(frozen=True)
class EntityMention:
    id: int
    text: str
    type: str
    start: int  # character offsets into the document text: text == document[start:end]
    end: int
    sentence: int
    origin: Literal["rules", "llm"]


@dataclass(frozen=True)
class RelationTriple:
    source: int  # EntityMention.id
    relation: str
    target: int
    sentence: int


@dataclass(frozen=True)
class DocumentExtraction:
    entities: tuple[EntityMention, ...]
    relations: tuple[RelationTriple, ...]
    sentences: int
    llm_failures: int
    warnings: tuple[str, ...] = ()
    dropped: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Sentence:
    index: int
    start: int  # character offset of the sentence in the document
    tokenized: str
    offsets: list[tuple[int, int]]  # per token, relative to the sentence
    rule_spans: list[Span]
    rule_triples: list[IndexTriple]


def _prepare(text: str, matcher: RuleMatcher, ontology: Ontology) -> list[_Sentence]:
    sentences: list[_Sentence] = []
    cursor = 0
    for index, sentence in enumerate(split_sentences(text)):
        # split_sentences returns slices of text.strip(), so each is found at or after cursor.
        start = text.find(sentence, cursor)
        cursor = start + len(sentence)
        tokenized = tokenize(sentence)
        spans, triples = matcher.find(tokenized, ontology.entity_names)
        offsets = token_offsets(sentence, tokenized.split())
        sentences.append(_Sentence(index, start, tokenized, offsets, spans, triples))
    return sentences


async def extract_text(
    text: str,
    matcher: RuleMatcher,
    ontology: Ontology,
    llm: SentenceExtractor | None = None,
) -> DocumentExtraction:
    sentences = _prepare(text, matcher, ontology)

    async def ask(s: _Sentence) -> tuple[list[Entity], list[SurfaceTriple], Exception | None]:
        if llm is None:
            return [], [], None
        try:
            entities, triples = await llm.extract(s.tokenized, known=s.rule_spans)
        except Exception as exc:  # noqa: BLE001 - one bad sentence must not sink the document
            return [], [], exc
        return entities, triples, None

    answers = await asyncio.gather(*(ask(s) for s in sentences))

    entities: list[EntityMention] = []
    relations: list[RelationTriple] = []
    warnings: list[str] = []
    dropped: list[str] = []
    failures = 0

    for s, (llm_entities, llm_triples, error) in zip(sentences, answers, strict=True):
        if error is not None:
            failures += 1
            warnings.append(
                f"sentence {s.index}: LLM failed "
                f"({type(error).__name__}: {str(error)[:200]}); rules only"
            )

        from_rules = {(span[0], span[1]) for span in s.rule_spans}
        spans = sorted(
            s.rule_spans + locate_spans(s.tokenized, llm_entities, taken=s.rule_spans),
            key=lambda span: span[0],
        )
        position = {(span[0], span[1]): k for k, span in enumerate(spans)}
        triples: list[IndexTriple] = [
            (
                position[(s.rule_spans[a][0], s.rule_spans[a][1])],
                rel,
                position[(s.rule_spans[b][0], s.rule_spans[b][1])],
            )
            for a, rel, b in s.rule_triples
        ]
        triples += resolve_triples(spans, llm_triples)

        kept, valid, removed = validate(spans, triples, ontology)
        dropped += [f"sentence {s.index}: {reason}" for reason in removed]

        base = len(entities)
        for start_token, end_token, _surface, type_ in kept:
            start = s.start + s.offsets[start_token][0]
            end = s.start + s.offsets[end_token - 1][1]
            origin: Literal["rules", "llm"] = (
                "rules" if (start_token, end_token) in from_rules else "llm"
            )
            entities.append(
                EntityMention(len(entities), text[start:end], type_, start, end, s.index, origin)
            )
        relations += [RelationTriple(base + a, rel, base + b, s.index) for a, rel, b in valid]

    return DocumentExtraction(
        tuple(entities),
        tuple(relations),
        len(sentences),
        failures,
        tuple(warnings),
        tuple(dropped),
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/extraction -v`
Expected: all PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add src/crawler/extraction/pipeline.py tests/extraction/test_extract_pipeline.py
git commit -m "feat: document extraction pipeline with character offsets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Batch runner: choose documents, write JSON atomically, stop on a dead LLM

**Files:**
- Create: `src/crawler/extraction/runner.py`
- Create: `tests/extraction/test_runner.py`

**Interfaces:**
- Consumes: `extract_text`, `DocumentExtraction`, `SentenceExtractor` (Task 8); `Ontology.version` (Task 3); `RuleMatcher` (Task 4)
- Produces:
  - `MAX_CONSECUTIVE_DEAD_DOCUMENTS = 3`
  - `class ExtractionAborted(RuntimeError)`
  - `DocumentRow(id: int, url: str, url_hash: str, source: str, title: str | None, published_at: datetime | None, body_text: str)`
  - `Summary(written: int = 0, failed: int = 0)`
  - `output_path(out_dir: Path, url_hash: str) -> Path`
  - `select_pending(candidates: Iterable[tuple[int, str]], out_dir: Path, limit: int, force: bool) -> list[int]`
  - `build_record(row: DocumentRow, result: DocumentExtraction, ontology_version: str, llm_model: str | None, extracted_at: datetime) -> dict[str, Any]`
  - `write_record(record: dict[str, Any], out_dir: Path) -> Path`
  - `async process(rows: Sequence[DocumentRow], out_dir: Path, matcher: RuleMatcher, ontology: Ontology, llm: SentenceExtractor | None, echo: Callable[[str], None] = print, now: Callable[[], datetime] = ...) -> Summary`

**Output file `data/extracted/<url_hash>.json`:**

```json
{
 "document_id": 42, "url": "https://…", "url_hash": "…", "source": "unit42",
 "title": "…", "published_at": "2026-09-01T00:00:00+00:00",
 "extracted_at": "2026-10-04T12:00:00+00:00", "ontology_version": "2026-10-04",
 "llm_model": "ministral-14b-latest", "sentences": 37,
 "entities": [{"id": 0, "text": "APT28", "type": "ThreatGroup", "start": 120, "end": 125,
               "sentence": 3, "origin": "rules"}],
 "relations": [{"source": 0, "relation": "uses", "target": 1, "sentence": 3}],
 "warnings": [], "dropped": ["sentence 5: X-Agent targets banks: ontology does not allow …"]
}
```

**Failure policy:**
- A document with any LLM-failed sentence is not written, so the next run retries it.
- Three documents in a row where every sentence failed raise `ExtractionAborted`. That pattern means the provider is down, out of quota, or rejecting the key or schema.
- With `llm=None` (`--rules-only`) nothing can fail.

- [ ] **Step 1: Write the failing tests** — `tests/extraction/test_runner.py`

```python
import json
from datetime import datetime, timezone

import pytest

from crawler.extraction.pipeline import DocumentExtraction, EntityMention, RelationTriple
from crawler.extraction.rules import RuleMatcher
from crawler.extraction.runner import (
    DocumentRow,
    ExtractionAborted,
    Summary,
    build_record,
    output_path,
    process,
    select_pending,
    write_record,
)

MATCHER = RuleMatcher(
    [
        {"name": "APT28", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
        {"name": "X-Agent", "type": "Malware", "id": "S0161", "case_sensitive": True},
    ]
)
NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)


def row(n: int, body: str = "APT28 used X-Agent.") -> DocumentRow:
    return DocumentRow(
        id=n,
        url=f"https://example.org/{n}",
        url_hash=f"{n:064x}",
        source="unit42",
        title=f"Post {n}",
        published_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        body_text=body,
    )


class FakeLLM:
    model_name = "model-a"

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def extract(self, sentence, known=()):
        if self.fail:
            raise RuntimeError("HTTP 401: bad key")
        return [], [("APT28", "uses", "X-Agent")]


def test_select_pending_skips_existing_output_and_respects_the_limit(tmp_path):
    output_path(tmp_path, "b").write_text("{}", encoding="utf-8")
    candidates = [(1, "a"), (2, "b"), (3, "c"), (4, "d")]

    assert select_pending(candidates, tmp_path, limit=2, force=False) == [1, 3]
    assert select_pending(candidates, tmp_path, limit=10, force=True) == [1, 2, 3, 4]


def test_temp_files_do_not_count_as_extracted(tmp_path):
    (tmp_path / ".extract-123.tmp").write_text("{", encoding="utf-8")
    assert select_pending([(1, "a")], tmp_path, limit=5, force=False) == [1]


def test_build_record_shape():
    result = DocumentExtraction(
        entities=(EntityMention(0, "APT28", "ThreatGroup", 0, 5, 0, "rules"),),
        relations=(RelationTriple(0, "alias-of", 0, 0),),
        sentences=1,
        llm_failures=0,
        dropped=("sentence 0: x",),
    )
    record = build_record(row(7), result, "v1", "model-a", NOW)

    assert record == {
        "document_id": 7,
        "url": "https://example.org/7",
        "url_hash": f"{7:064x}",
        "source": "unit42",
        "title": "Post 7",
        "published_at": "2026-09-01T00:00:00+00:00",
        "extracted_at": "2026-10-04T12:00:00+00:00",
        "ontology_version": "v1",
        "llm_model": "model-a",
        "sentences": 1,
        "entities": [
            {
                "id": 0,
                "text": "APT28",
                "type": "ThreatGroup",
                "start": 0,
                "end": 5,
                "sentence": 0,
                "origin": "rules",
            }
        ],
        "relations": [{"source": 0, "relation": "alias-of", "target": 0, "sentence": 0}],
        "warnings": [],
        "dropped": ["sentence 0: x"],
    }


def test_write_record_round_trips_and_overwrites(tmp_path):
    path = write_record({"url_hash": "abc", "v": 1}, tmp_path / "out")
    write_record({"url_hash": "abc", "v": 2}, tmp_path / "out")

    assert path == tmp_path / "out" / "abc.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {"url_hash": "abc", "v": 2}
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["abc.json"]


def test_failed_write_leaves_no_file(tmp_path):
    with pytest.raises(TypeError):
        write_record({"url_hash": "abc", "bad": object()}, tmp_path)
    assert list(tmp_path.iterdir()) == []


async def test_process_writes_one_file_per_document(tmp_path, ontology):
    lines: list[str] = []

    summary = await process(
        [row(1), row(2)], tmp_path, MATCHER, ontology, FakeLLM(), lines.append, lambda: NOW
    )

    assert summary == Summary(written=2, failed=0)
    record = json.loads(output_path(tmp_path, f"{1:064x}").read_text(encoding="utf-8"))
    assert [e["text"] for e in record["entities"]] == ["APT28", "X-Agent"]
    assert record["relations"] == [{"source": 0, "relation": "uses", "target": 1, "sentence": 0}]
    assert record["llm_model"] == "model-a"
    assert record["ontology_version"] == ontology.version
    assert len(lines) == 2 and "entities=2" in lines[0]


async def test_rules_only_records_no_model(tmp_path, ontology):
    await process([row(1)], tmp_path, MATCHER, ontology, None, lambda line: None, lambda: NOW)
    record = json.loads(output_path(tmp_path, f"{1:064x}").read_text(encoding="utf-8"))
    assert record["llm_model"] is None and record["relations"] == []


async def test_documents_with_llm_failures_are_not_written(tmp_path, ontology):
    lines: list[str] = []

    summary = await process([row(1)], tmp_path, MATCHER, ontology, FakeLLM(fail=True), lines.append)

    assert summary == Summary(written=0, failed=1)
    assert list(tmp_path.iterdir()) == []
    assert "FAILED 1/1 sentences" in lines[0]
    assert select_pending([(1, f"{1:064x}")], tmp_path, limit=5, force=False) == [1]


async def test_three_dead_documents_in_a_row_abort(tmp_path, ontology):
    rows = [row(n) for n in range(1, 6)]

    with pytest.raises(ExtractionAborted, match="3 documents in a row.*bad key"):
        await process(rows, tmp_path, MATCHER, ontology, FakeLLM(fail=True), lambda line: None)
    assert list(tmp_path.iterdir()) == []


async def test_a_partial_failure_does_not_count_toward_the_abort(tmp_path, ontology):
    class Flaky:
        model_name = "m"

        async def extract(self, sentence, known=()):
            if "first" in sentence:
                raise RuntimeError("blip")
            return [], []

    rows = [row(n, "The first one. APT28 used X-Agent.") for n in range(1, 5)]
    summary = await process(rows, tmp_path, MATCHER, ontology, Flaky(), lambda line: None)
    assert summary == Summary(written=0, failed=4)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/extraction/test_runner.py -v`
Expected: collection error, `No module named 'crawler.extraction.runner'`

- [ ] **Step 3: Implement** — `src/crawler/extraction/runner.py`

```python
"""Batch extraction: pick documents, run the pipeline, write one JSON file per document.

A file at <out>/<url_hash>.json is what marks a document as extracted; the database is not
touched. Files are written atomically, and a document whose LLM pass failed anywhere is not
written at all, so an interrupted or degraded run is simply resumed by running again.
"""

import json
import os
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crawler.extraction.ontology import Ontology
from crawler.extraction.pipeline import DocumentExtraction, SentenceExtractor, extract_text
from crawler.extraction.rules import RuleMatcher

# A provider that fails every sentence of this many documents in a row is down, out of quota,
# or rejecting our key or schema. Stop, rather than walk the backlog writing nothing.
MAX_CONSECUTIVE_DEAD_DOCUMENTS = 3


class ExtractionAborted(RuntimeError):
    """The LLM failed every sentence of several documents in a row."""


@dataclass(frozen=True)
class DocumentRow:
    id: int
    url: str
    url_hash: str
    source: str
    title: str | None
    published_at: datetime | None
    body_text: str


@dataclass(frozen=True)
class Summary:
    written: int = 0
    failed: int = 0


def output_path(out_dir: Path, url_hash: str) -> Path:
    return Path(out_dir) / f"{url_hash}.json"


def select_pending(
    candidates: Iterable[tuple[int, str]], out_dir: Path, limit: int, force: bool
) -> list[int]:
    """Ids of the first `limit` candidates without an output file (any candidate with force)."""
    chosen: list[int] = []
    for doc_id, url_hash in candidates:
        if len(chosen) >= limit:
            break
        if force or not output_path(out_dir, url_hash).exists():
            chosen.append(doc_id)
    return chosen


def build_record(
    row: DocumentRow,
    result: DocumentExtraction,
    ontology_version: str,
    llm_model: str | None,
    extracted_at: datetime,
) -> dict[str, Any]:
    return {
        "document_id": row.id,
        "url": row.url,
        "url_hash": row.url_hash,
        "source": row.source,
        "title": row.title,
        "published_at": row.published_at.isoformat() if row.published_at else None,
        "extracted_at": extracted_at.isoformat(),
        "ontology_version": ontology_version,
        "llm_model": llm_model,
        "sentences": result.sentences,
        "entities": [asdict(e) for e in result.entities],
        "relations": [asdict(r) for r in result.relations],
        "warnings": list(result.warnings),
        "dropped": list(result.dropped),
    }


def write_record(record: dict[str, Any], out_dir: Path) -> Path:
    """Write atomically: a crash mid-write must not leave a file that reads as extracted."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = output_path(out_dir, record["url_hash"])
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".extract-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def process(
    rows: Sequence[DocumentRow],
    out_dir: Path,
    matcher: RuleMatcher,
    ontology: Ontology,
    llm: SentenceExtractor | None,
    echo: Callable[[str], None] = print,
    now: Callable[[], datetime] = _utc_now,
) -> Summary:
    written = failed = dead_streak = 0
    for row in rows:
        result = await extract_text(row.body_text, matcher, ontology, llm)
        label = f"{row.source:<16} {row.url_hash[:12]}"

        if result.llm_failures:
            failed += 1
            echo(
                f"{label} FAILED {result.llm_failures}/{result.sentences} sentences: "
                f"{result.warnings[0]}"
            )
            all_failed = result.llm_failures == result.sentences
            dead_streak = dead_streak + 1 if all_failed else 0
            if dead_streak >= MAX_CONSECUTIVE_DEAD_DOCUMENTS:
                raise ExtractionAborted(
                    f"LLM failed every sentence of {dead_streak} documents in a row; "
                    f"last error: {result.warnings[-1]}"
                )
            continue

        dead_streak = 0
        record = build_record(
            row, result, ontology.version, getattr(llm, "model_name", None), now()
        )
        write_record(record, out_dir)
        written += 1
        echo(f"{label} entities={len(result.entities):<4} relations={len(result.relations)}")
    return Summary(written, failed)
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/extraction/test_runner.py -v`
Expected: all PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
git add src/crawler/extraction/runner.py tests/extraction/test_runner.py
git commit -m "feat: batch runner with atomic JSON output and dead-LLM abort

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: `crawler extract` command, document query, and docs

**Files:**
- Modify: `src/crawler/extraction/runner.py` (add `load_pending`, `run`)
- Modify: `src/crawler/cli.py` (add `extract`)
- Modify: `src/crawler/config.py` (add `extracted_dir`)
- Modify: `.gitignore`, `README.md`
- Create: `tests/test_cli_extract.py`
- Create: `tests/db/test_pending_documents.py`

**Interfaces:**
- Consumes: everything above; `Document` ORM model; `session_scope`; `DomainRateLimiter`; `RateLimit`
- Produces:
  - `load_pending(session: Session, out_dir: Path, sources: Sequence[str] | None, limit: int, force: bool) -> list[DocumentRow]` (documents with non-empty `body_text`, ordered by id)
  - `async run(settings: Settings, sources: Sequence[str] | None, limit: int, out_dir: Path, rules_only: bool, force: bool, echo: Callable[[str], None]) -> Summary`
  - CLI: `crawler extract [--source a,b] [--limit 50] [--out DIR] [--rules-only] [--force]`
  - `Settings.extracted_dir: Path = Path("data/extracted")`

- [ ] **Step 1: Write the failing tests**

`tests/test_cli_extract.py`:

```python
import json
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from crawler import cli
from crawler.config import get_settings
from crawler.extraction import runner


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x@127.0.0.1:1/none")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@contextmanager
def no_database():
    yield object()


def test_extract_rules_only_writes_files(monkeypatch, tmp_path):
    rows = [
        runner.DocumentRow(
            id=1,
            url="https://e.org/1",
            url_hash="a" * 64,
            source="unit42",
            title="T",
            published_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            body_text="APT28 deployed X-Agent against CVE-2017-11882 in March 2019.",
        )
    ]
    seen = {}

    def fake_load_pending(session, out_dir, sources, limit, force):
        seen.update(sources=sources, limit=limit, force=force, out_dir=out_dir)
        return rows

    monkeypatch.setattr(runner, "session_scope", no_database)
    monkeypatch.setattr(runner, "load_pending", fake_load_pending)

    result = CliRunner().invoke(
        cli.app,
        ["extract", "--rules-only", "--out", str(tmp_path), "--source", "unit42, kev", "--limit", "5"],
    )

    assert result.exit_code == 0, result.output
    assert seen == {"sources": ["unit42", "kev"], "limit": 5, "force": False, "out_dir": tmp_path}
    record = json.loads((tmp_path / f"{'a' * 64}.json").read_text(encoding="utf-8"))
    assert {e["type"] for e in record["entities"]} >= {"Vulnerability", "Time"}
    assert "Wrote 1 files" in result.output


def test_missing_api_key_fails_before_the_database(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_PROVIDER", "grok")
    monkeypatch.setenv("GROK_API_KEY", "")

    def must_not_query(*args, **kwargs):
        raise AssertionError("database queried before the key was checked")

    monkeypatch.setattr(runner, "load_pending", must_not_query)

    result = CliRunner().invoke(cli.app, ["extract", "--out", str(tmp_path)])

    assert result.exit_code == 1
    assert "GROK_API_KEY is not set" in result.output


def test_nothing_to_extract(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "session_scope", no_database)
    monkeypatch.setattr(runner, "load_pending", lambda *args: [])

    result = CliRunner().invoke(cli.app, ["extract", "--rules-only", "--out", str(tmp_path)])

    assert result.exit_code == 0
    assert "Nothing to extract." in result.output
```

`tests/db/test_pending_documents.py` (runs only with `TEST_DATABASE_URL`, like the other DB tests):

```python
from datetime import datetime, timezone

from crawler.db.schema import Document, Source
from crawler.extraction.runner import load_pending, output_path

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def add(session, n: int, source: str, body: str | None) -> Document:
    doc = Document(
        source=source,
        url=f"https://e.org/{n}",
        url_hash=f"{n:064x}",
        title=f"T{n}",
        body_text=body,
        fetched_at=NOW,
        license="copyrighted",
    )
    session.add(doc)
    session.flush()
    return doc


def test_load_pending_selects_unextracted_documents_with_text(db_session, tmp_path):
    db_session.add_all(
        [Source(name="s1", kind="feed", license="c"), Source(name="s2", kind="feed", license="c")]
    )
    db_session.flush()
    done = add(db_session, 1, "s1", "already extracted")
    empty = add(db_session, 2, "s1", "")
    null = add(db_session, 3, "s1", None)
    todo = add(db_session, 4, "s1", "APT28 used X-Agent.")
    other = add(db_session, 5, "s2", "Lazarus used PlugX.")
    output_path(tmp_path, done.url_hash).write_text("{}", encoding="utf-8")

    rows = load_pending(db_session, tmp_path, None, limit=10, force=False)
    assert [r.id for r in rows] == [todo.id, other.id]
    assert rows[0].body_text == "APT28 used X-Agent." and rows[0].source == "s1"

    assert [r.id for r in load_pending(db_session, tmp_path, ["s2"], 10, False)] == [other.id]
    assert [r.id for r in load_pending(db_session, tmp_path, None, 1, False)] == [todo.id]
    forced = load_pending(db_session, tmp_path, None, 10, True)
    assert [r.id for r in forced] == [done.id, todo.id, other.id]
    assert empty.id not in {r.id for r in forced} and null.id not in {r.id for r in forced}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_cli_extract.py -v`
Expected: FAIL. `No such command 'extract'` (exit code 2) and `AttributeError: ... has no attribute 'session_scope'` on the monkeypatch.

- [ ] **Step 3: Implement**

In `src/crawler/config.py`, add to `Settings` after `ontology_path`:

```python
    extracted_dir: Path = Path("data/extracted")
```

Append to `src/crawler/extraction/runner.py`, and add these imports to its import block (ruff will sort them):

```python
import asyncio

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from crawler.config import Settings
from crawler.core.models import RateLimit
from crawler.core.ratelimit import DomainRateLimiter
from crawler.db.schema import Document
from crawler.db.session import session_scope
from crawler.extraction.client import build_chat_client
from crawler.extraction.llm import LLMExtractor
from crawler.extraction.ontology import load_ontology
from crawler.extraction.rules import load_matcher
```

```python
def load_pending(
    session: Session,
    out_dir: Path,
    sources: Sequence[str] | None,
    limit: int,
    force: bool,
) -> list[DocumentRow]:
    """Documents with body text and no output file yet, oldest id first.

    Ids and hashes are read first and filtered against the output directory, so only the
    bodies that will actually be extracted are loaded.
    """
    has_text = func.length(func.coalesce(Document.body_text, "")) > 0
    query = select(Document.id, Document.url_hash).where(has_text).order_by(Document.id)
    if sources:
        query = query.where(Document.source.in_(sources))
    ids = select_pending(session.execute(query).tuples(), out_dir, limit, force)
    if not ids:
        return []

    rows = session.execute(
        select(
            Document.id,
            Document.url,
            Document.url_hash,
            Document.source,
            Document.title,
            Document.published_at,
            Document.body_text,
        )
        .where(Document.id.in_(ids))
        .order_by(Document.id)
    ).tuples()
    return [DocumentRow(*row) for row in rows]


async def run(
    settings: Settings,
    sources: Sequence[str] | None,
    limit: int,
    out_dir: Path,
    rules_only: bool,
    force: bool,
    echo: Callable[[str], None],
) -> Summary:
    ontology = load_ontology(settings.ontology_path)
    matcher = load_matcher()

    async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
        llm: LLMExtractor | None = None
        if not rules_only:
            # Built before the database is touched: a missing key should fail in a second.
            limiter = DomainRateLimiter(
                default=RateLimit(requests=settings.llm_requests_per_minute, per_seconds=60.0)
            )
            chat = build_chat_client(
                settings, client, limiter, asyncio.Semaphore(settings.llm_parallel)
            )
            llm = LLMExtractor(chat, ontology)

        with session_scope() as session:
            rows = load_pending(session, out_dir, sources, limit, force)
        if not rows:
            echo("Nothing to extract.")
            return Summary()

        mode = "rules only" if rules_only else f"{settings.llm_provider} LLM"
        echo(f"Extracting {len(rows)} documents ({mode}) into {out_dir}")
        return await process(rows, out_dir, matcher, ontology, llm, echo)
```

In `src/crawler/cli.py`, add after the `export` command:

```python
@app.command()
def extract(
    source: str | None = typer.Option(None, help="Comma-separated source names."),
    limit: int = typer.Option(50, min=1, help="Extract at most this many documents."),
    out: Path | None = typer.Option(None, "--out", help="Output directory [data/extracted]."),
    rules_only: bool = typer.Option(False, "--rules-only", help="Skip the LLM pass."),
    force: bool = typer.Option(False, "--force", help="Redo documents that already have output."),
) -> None:
    """Extract CTI entities and relations into <out>/<url_hash>.json, one file per document."""
    from crawler.extraction import runner
    from crawler.extraction.client import LLMError
    from crawler.extraction.ontology import OntologyError

    settings = get_settings()
    names = [n.strip() for n in source.split(",") if n.strip()] if source else None
    out_dir = out or settings.extracted_dir

    try:
        summary = asyncio.run(
            runner.run(settings, names, limit, out_dir, rules_only, force, typer.echo)
        )
    except (LLMError, OntologyError, runner.ExtractionAborted) as exc:
        typer.secho(f"FAILED: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    colour = typer.colors.YELLOW if summary.failed else typer.colors.GREEN
    typer.secho(
        f"Wrote {summary.written} files; {summary.failed} documents failed "
        "and will be retried on the next run.",
        fg=colour,
    )
```

`.gitignore`: under `data/export/`, add `data/extracted/`.

`README.md`: replace the `## Usage` section with:

````markdown
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
````

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_cli_extract.py tests/db/test_pending_documents.py -v`
Expected: the CLI tests PASS. `test_pending_documents` ERRORs with `OperationalError` if Postgres is down (like every DB test) and PASSes with `docker compose up -d`.

- [ ] **Step 5: Full suite, lint, and a real rules-only run**

```bash
uv run pytest -q
uv run ruff format $(git ls-files --others --exclude-standard -- '*.py') && uv run ruff check src tests
uv run ruff format --check src/crawler/extraction src/crawler/sources/catalog.py src/crawler/sources/loader.py
uv run crawler extract --help
```

Expected: no failures beyond DB `OperationalError`s when Postgres is down; ruff clean; help lists `--source --limit --out --rules-only --force`.

If Postgres is up, run `uv run crawler extract --rules-only --limit 3`. Expected: three `entities=…` lines, `Wrote 3 files`, and three JSON files in `data/extracted/`. For each file, `body_text[start:end] == text` holds for every entity.

- [ ] **Step 6: Commit**

```bash
git add src/crawler/extraction/runner.py src/crawler/cli.py src/crawler/config.py .gitignore README.md tests/test_cli_extract.py tests/db/test_pending_documents.py
git commit -m "feat: crawler extract command writing data/extracted/<url_hash>.json

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

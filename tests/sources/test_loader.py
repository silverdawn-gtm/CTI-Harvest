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
            KevConfig(
                name="d", adapter="kev", entry_url="https://d.example/k.json", rate_limit=SLOW
            ),
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
    source = build_source(
        KevConfig(name="kev", adapter="kev", entry_url="https://m.example/k.json")
    )

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

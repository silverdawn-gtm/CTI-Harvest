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
            return KevSource(
                config.name, config.entry_url, rate_limit=limit, license=config.license
            )
        case NvdConfig():
            return NvdSource(
                config.name, config.entry_url, rate_limit=limit, license=config.license
            )
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

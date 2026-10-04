"""One adapter, many publications.

Security news sites differ only in feed URL, so adding a publication is an entry in
config/sources.yaml rather than a new module. Each site registers as its own `Source` so it
gets its own `last_success_at`, its own circuit breaker, and its own row in `stats`.
"""

import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import feedparser
import trafilatura

from crawler.core.models import DiscoveredItem, ParsedDoc, ParseResult, RawDocument
from crawler.sources.base import RateLimit

logger = logging.getLogger(__name__)

# Below this, treat the extraction as failed and fall back to the feed summary. Real security
# articles run to thousands of characters; a few hundred means the selectors missed.
MIN_BODY_CHARS = 200

def _entry_published(entry) -> datetime | None:
    """Feed dates arrive as struct_time in UTC, or not at all."""
    parsed = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
    if not parsed:
        return None
    return datetime(*parsed[:6], tzinfo=timezone.utc)


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

    async def discover(
        self, since: datetime, fetcher=None, mode: str = "incremental"
    ) -> AsyncIterator[DiscoveredItem]:
        if fetcher is None:  # pragma: no cover - programming error, not a runtime condition
            raise ValueError(f"{self.name}: discover requires a fetcher to read the feed")

        raw = await fetcher.fetch(DiscoveredItem(url=self.feed_url, source=self.name))
        if raw is None:  # 304 Not Modified on the feed itself
            return

        feed = feedparser.parse(raw.content)
        for entry in feed.entries:
            link = getattr(entry, "link", None)
            if not link:
                continue

            published = _entry_published(entry)
            if published is not None and published < since:
                continue

            yield DiscoveredItem(
                url=link,
                source=self.name,
                published_at=published,
                title=getattr(entry, "title", None),
                # Carried so parse() can fall back to it when body extraction comes up short.
                hint={"summary": getattr(entry, "summary", "") or ""},
            )

    def parse(self, raw: RawDocument) -> ParseResult:
        html = raw.content.decode("utf-8", errors="replace")
        body = trafilatura.extract(html, include_comments=False, include_tables=False) or ""
        warnings: list[str] = []

        if len(body) < MIN_BODY_CHARS:
            summary = raw.item.hint.get("summary", "")
            warnings.append(
                f"body extraction returned {len(body)} chars; fell back to feed summary"
            )
            body = summary or body

        title = raw.item.title or "(untitled)"
        if not raw.item.title:
            warnings.append("feed entry had no title")

        if not body:
            warnings.append("no body text recovered")

        return ParseResult(
            documents=(
                ParsedDoc(
                    url=raw.item.url,
                    source=self.name,
                    title=title,
                    body_text=body,
                    license=self.license,
                    published_at=raw.item.published_at,
                    warnings=tuple(warnings),
                ),
            )
        )


"""Publishers reachable only through their sitemaps.

RSS returns whatever a feed currently holds -- usually a few weeks. A sitemap lists the whole
archive, which is the only way to reach two years of history on sites that block the
WordPress API.

The cost is one request per article, so date filtering happens during discovery, before
anything is fetched. Sites that publish `lastmod` are filtered on it directly; the rest carry
the date in the URL (`/2026/08/slug`), which is just as good and free.
"""

import gzip
import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone

from crawler.core.article import MIN_BODY_CHARS, extract_body
from crawler.core.fetch import FetchError
from crawler.core.models import DiscoveredItem, ParsedDoc, ParseResult, RateLimit, RawDocument

logger = logging.getLogger(__name__)

_SITEMAP_BLOCK = re.compile(r"<sitemap>(.*?)</sitemap>", re.S | re.I)
_URL_BLOCK = re.compile(r"<url>(.*?)</url>", re.S | re.I)
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_LASTMOD = re.compile(r"<lastmod>\s*([^<\s]+)", re.I)
_URL_DATE = re.compile(r"/(20\d{2})/(\d{2})/")

# A single publication's two-year archive. Guards against a malformed index sending the
# crawler through tens of thousands of URLs.
MAX_ARTICLES = 6000


def _text(raw: bytes) -> str:
    """Sitemaps are sometimes served gzipped regardless of the URL suffix."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", errors="replace")


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _url_month(url: str) -> datetime | None:
    match = _URL_DATE.search(url)
    if not match:
        return None
    year, month = int(match.group(1)), int(match.group(2))
    if not 1 <= month <= 12:
        return None
    return datetime(year, month, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class SitemapSite:
    name: str
    index: str
    child: str  # substring identifying child sitemaps that hold articles
    article: str = ""  # substring every article URL contains; "" accepts all


DEFAULT_RATE_LIMIT = RateLimit(requests=1, per_seconds=2.0)


class SitemapSource:
    kind = "html"

    def __init__(
        self,
        site: SitemapSite,
        rate_limit: RateLimit = DEFAULT_RATE_LIMIT,
        license: str = "copyrighted",
    ) -> None:
        self._site = site
        self.name = site.name
        self.entry_url = site.index
        self.rate_limit = rate_limit
        self.license = license

    async def discover(
        self, since: datetime, fetcher=None, mode: str = "incremental"
    ) -> AsyncIterator[DiscoveredItem]:
        if fetcher is None:  # pragma: no cover - programming error, not a runtime condition
            raise ValueError(f"{self.name}: discover requires a fetcher")

        index = await self._get(fetcher, self._site.index)
        if index is None:
            return

        children = [
            loc
            for block in _SITEMAP_BLOCK.findall(index)
            for loc in _LOC.findall(block)
            if self._site.child in loc
        ]
        if not children:
            logger.warning("%s: no child sitemaps matched %r", self.name, self._site.child)
            return

        seen: set[str] = set()
        emitted = 0

        for child in children:
            body = await self._get(fetcher, child)
            if body is None:
                continue

            for block in _URL_BLOCK.findall(body):
                locs = _LOC.findall(block)
                if not locs:
                    continue
                url = locs[0]

                if self._site.article and self._site.article not in url:
                    continue
                if url in seen:
                    continue

                published = _when(_LASTMOD.search(block).group(1)) if _LASTMOD.search(
                    block
                ) else None
                # Fall back to the date in the URL path so archives without lastmod can still
                # be date-bounded rather than crawled end to end.
                bound = published or _url_month(url)
                if bound is not None and bound < since:
                    continue

                seen.add(url)
                emitted += 1
                if emitted > MAX_ARTICLES:
                    logger.warning("%s: hit MAX_ARTICLES=%d, stopping", self.name, MAX_ARTICLES)
                    return

                yield DiscoveredItem(url=url, source=self.name, published_at=published)

        logger.info("%s: %d articles in range", self.name, emitted)

    async def _get(self, fetcher, url: str) -> str | None:
        try:
            raw = await fetcher.fetch(DiscoveredItem(url=url, source=self.name))
        except FetchError as exc:
            logger.warning("%s: could not read %s (%s)", self.name, url, exc)
            return None
        return None if raw is None else _text(raw.content)

    def parse(self, raw: RawDocument) -> ParseResult:
        body = extract_body(raw.content.decode("utf-8", errors="replace"))
        warnings: list[str] = []

        if len(body) < MIN_BODY_CHARS:
            warnings.append(f"body extraction returned only {len(body)} chars")
            if not body:
                return ParseResult(warnings=tuple(warnings))

        return ParseResult(
            documents=(
                ParsedDoc(
                    url=raw.item.url,
                    source=self.name,
                    title=raw.item.title or _title(raw) or "(untitled)",
                    body_text=body,
                    license=self.license,
                    published_at=raw.item.published_at,
                    warnings=tuple(warnings),
                ),
            )
        )


_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


def _title(raw: RawDocument) -> str | None:
    """Sitemaps carry no titles, so recover one from the page itself."""
    import html as _html

    match = _TITLE.search(raw.content.decode("utf-8", errors="replace"))
    if not match:
        return None
    return _html.unescape(re.sub(r"\s+", " ", match.group(1))).strip() or None


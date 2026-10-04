"""Publishers that expose the WordPress REST API.

Worth its own adapter because the economics are completely different from RSS: one request
returns 100 posts with full body text, so two years of a publication costs ~20 requests
instead of ~2,000. Where a site offers this, it is always the polite option.
"""

import html
import json
import logging
import re
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import trafilatura

from crawler.core.fetch import FetchError
from crawler.core.models import DiscoveredItem, ParsedDoc, ParseResult, RawDocument
from crawler.sources.base import RateLimit

logger = logging.getLogger(__name__)

PER_PAGE = 100
MAX_PAGES = 200  # Backstop: 20,000 posts is far beyond any of these publications.
_TAGS = re.compile(r"<[^>]+>")

def _text(fragment: str) -> str:
    return html.unescape(_TAGS.sub("", fragment or "")).strip()


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # date_gmt has no offset; it is UTC by definition.
        return datetime.fromisoformat(value.rstrip("Z")).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


DEFAULT_RATE_LIMIT = RateLimit(requests=1, per_seconds=2.0)


class WordPressSource:
    kind = "api"

    def __init__(
        self,
        name: str,
        api: str,
        rate_limit: RateLimit = DEFAULT_RATE_LIMIT,
        license: str = "copyrighted",
    ) -> None:
        self.name = name
        self.api = api
        self.entry_url = api
        self.rate_limit = rate_limit
        self.license = license

    def _page_url(self, since: datetime, page: int) -> str:
        after = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        return f"{self.api}?after={after}&per_page={PER_PAGE}&page={page}&orderby=date&order=desc"

    async def discover(
        self, since: datetime, fetcher=None, mode: str = "incremental"
    ) -> AsyncIterator[DiscoveredItem]:
        if fetcher is None:  # pragma: no cover - programming error, not a runtime condition
            raise ValueError(f"{self.name}: discover requires a fetcher")

        for page in range(1, MAX_PAGES + 1):
            url = self._page_url(since, page)
            try:
                raw = await fetcher.fetch(DiscoveredItem(url=url, source=self.name))
            except FetchError:
                # WordPress answers 400 past the last page. That is the stop signal, not a
                # failure -- letting it propagate would quarantine the whole source.
                logger.info("%s: stopped at page %d", self.name, page)
                return

            if raw is None:
                return

            try:
                posts = json.loads(raw.content)
            except json.JSONDecodeError:
                logger.warning("%s: page %d was not JSON", self.name, page)
                return

            if not isinstance(posts, list) or not posts:
                return

            yield DiscoveredItem(url=url, source=self.name)

            if len(posts) < PER_PAGE:
                return

    def parse(self, raw: RawDocument) -> ParseResult:
        posts = json.loads(raw.content)
        docs: list[ParsedDoc] = []
        warnings: list[str] = []

        for post in posts:
            link = post.get("link")
            if not link:
                warnings.append("post without a link skipped")
                continue

            rendered = (post.get("content") or {}).get("rendered") or ""
            body = trafilatura.extract(rendered, include_comments=False) or _text(rendered)
            title = _text((post.get("title") or {}).get("rendered")) or "(untitled)"

            if not body:
                warnings.append(f"no body recovered for {link}")
                continue

            docs.append(
                ParsedDoc(
                    url=link,
                    source=self.name,
                    title=title,
                    body_text=body,
                    license=self.license,
                    published_at=_when(post.get("date_gmt")),
                )
            )

        return ParseResult(documents=tuple(docs), warnings=tuple(warnings))


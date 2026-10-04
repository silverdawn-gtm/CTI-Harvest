"""NVD CVE feed.

The largest source in the project and the strictest rate limiter, so it is also the only one
that manages its own limit and pages by date window.
"""

import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from crawler.core.models import DiscoveredItem, ParseResult, RawDocument, VulnerabilityFact
from crawler.sources.base import RateLimit

logger = logging.getLogger(__name__)

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD refuses date ranges wider than 120 days, and returns at most 2000 results per request.
MAX_WINDOW_DAYS = 120
PAGE_SIZE = 2000

# Without an API key NVD allows 5 requests per 30 seconds. The published guidance is to leave
# several seconds between requests rather than burst; 6.5s keeps us comfortably legal.
NO_KEY_LIMIT = RateLimit(requests=1, per_seconds=6.5)


def _stamp(when: datetime) -> str:
    """NVD wants ISO-8601 with milliseconds and no timezone suffix."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _windows(since: datetime, until: datetime) -> list[tuple[datetime, datetime]]:
    out: list[tuple[datetime, datetime]] = []
    start = since
    while start < until:
        end = min(start + timedelta(days=MAX_WINDOW_DAYS), until)
        out.append((start, end))
        start = end
    return out


def _page_url(api: str, start: datetime, end: datetime, index: int, mode: str, size: int) -> str:
    # Backfill asks "what was published in this window"; an incremental run asks "what changed".
    # They return different sets: a lastMod query misses everything published long ago and
    # never touched since.
    prefix = "pub" if mode == "backfill" else "lastMod"
    return (
        f"{api}?{prefix}StartDate={_stamp(start)}&{prefix}EndDate={_stamp(end)}"
        f"&resultsPerPage={size}&startIndex={index}"
    )


class NvdSource:
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

    async def discover(
        self, since: datetime, fetcher=None, mode: str = "incremental"
    ) -> AsyncIterator[DiscoveredItem]:
        if fetcher is None:  # pragma: no cover - programming error, not a runtime condition
            raise ValueError("nvd: discover requires a fetcher to probe for result counts")

        # The shared default (1 req/2s) is three times faster than NVD permits, which earns a
        # 403 within seconds. Install our own limit for this host before any request goes out.
        fetcher.limiter.set_limit(urlparse(self.entry_url).netloc, self.rate_limit)

        until = datetime.now(timezone.utc)
        for start, end in _windows(since, until):
            total = await self._count(fetcher, start, end, mode)
            if total == 0:
                continue

            pages = -(-total // PAGE_SIZE)  # ceiling division
            logger.info(
                "nvd: %s..%s -> %d CVEs across %d pages",
                start.date(),
                end.date(),
                total,
                pages,
            )
            for page in range(pages):
                yield DiscoveredItem(
                    url=_page_url(self.entry_url, start, end, page * PAGE_SIZE, mode, PAGE_SIZE),
                    source=self.name,
                )

    async def _count(self, fetcher, start: datetime, end: datetime, mode: str) -> int:
        """Page count is only knowable from a response, so probe for totalResults first."""
        url = _page_url(self.entry_url, start, end, 0, mode, 1)
        probe = DiscoveredItem(url=url, source=self.name)
        raw = await fetcher.fetch(probe)
        if raw is None:
            return 0
        return int(json.loads(raw.content).get("totalResults", 0))

    def parse(self, raw: RawDocument) -> ParseResult:
        payload = json.loads(raw.content)
        facts: list[VulnerabilityFact] = []
        warnings: list[str] = []

        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                warnings.append("entry without a CVE id skipped")
                continue

            facts.append(
                VulnerabilityFact(
                    cve_id=cve_id,
                    vendor=_vendor(cve),
                    product=_product(cve),
                    description=_description(cve),
                    published=_published(cve),
                    cvss_v3=_score(cve),
                    cvss_vector=_vector(cve),
                )
            )

        if not facts:
            warnings.append("page contained no usable CVE entries")

        return ParseResult(vulnerabilities=tuple(facts), warnings=tuple(warnings))


def _description(cve: dict) -> str | None:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _published(cve: dict) -> datetime | None:
    value = cve.get("published")
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _metric(cve: dict) -> dict | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            return entries[0].get("cvssData") or {}
    return None


def _score(cve: dict) -> float | None:
    data = _metric(cve)
    return data.get("baseScore") if data else None


def _vector(cve: dict) -> str | None:
    data = _metric(cve)
    return data.get("vectorString") if data else None


def _cpe_parts(cve: dict) -> list[str]:
    """First CPE match in the configurations, split into its colon-delimited fields."""
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria.startswith("cpe:2.3:"):
                    return criteria.split(":")
    return []


def _vendor(cve: dict) -> str | None:
    parts = _cpe_parts(cve)
    return parts[3] if len(parts) > 4 else None


def _product(cve: dict) -> str | None:
    parts = _cpe_parts(cve)
    return parts[4] if len(parts) > 5 else None


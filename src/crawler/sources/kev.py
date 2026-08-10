import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from crawler.core.models import (
    DiscoveredItem,
    ParsedDoc,
    ParseResult,
    RawDocument,
    VulnerabilityFact,
)
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

    async def discover(
        self, since: datetime, fetcher=None, mode: str = "incremental"
    ) -> AsyncIterator[DiscoveredItem]:
        yield DiscoveredItem(url=self.CATALOG_URL, source=self.name)

    def parse(self, raw: RawDocument) -> ParseResult:
        payload = json.loads(raw.content)
        docs: list[ParsedDoc] = []
        facts: list[VulnerabilityFact] = []

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
                )
            )
            facts.append(
                VulnerabilityFact(
                    cve_id=cve_id,
                    vendor=entry.get("vendorProject"),
                    product=entry.get("product"),
                    description=entry.get("shortDescription"),
                    kev_listed=True,
                    kev_added_date=added,
                )
            )

        return ParseResult(documents=tuple(docs), vulnerabilities=tuple(facts))


register(KevSource())

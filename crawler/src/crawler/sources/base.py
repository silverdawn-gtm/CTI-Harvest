from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from crawler.core.models import DiscoveredItem, ParseResult, RateLimit, RawDocument

if TYPE_CHECKING:
    # Type-only: importing Fetcher at runtime would cycle back through core.ratelimit.
    from crawler.core.fetch import Fetcher

# Re-exported: adapters and tests import RateLimit from here, and it reads naturally
# alongside the Source protocol that declares it.
__all__ = ["RateLimit", "Source", "all_sources", "get_source", "register"]


@runtime_checkable
class Source(Protocol):
    name: str
    kind: Literal["feed", "api", "html", "pdf"]
    license: str
    # Where discovery starts. The loader installs `rate_limit` on this URL's host.
    entry_url: str
    rate_limit: RateLimit

    def discover(
        self,
        since: datetime,
        fetcher: "Fetcher | None" = None,
        mode: Literal["incremental", "backfill"] = "incremental",
    ) -> AsyncIterator[DiscoveredItem]:
        """Yield items to fetch that may have changed since `since`.

        Feed- and API-backed sources need `fetcher` to enumerate what exists: an RSS adapter
        must read the feed before it knows any article URLs. Sources that already know their
        URLs, like KEV, ignore it.

        `mode` matters where "what changed" and "what was published" are different questions.
        NVD backfills by publication date but runs incrementally by modification date; asking
        the wrong one silently returns the wrong set.
        """
        ...

    def parse(self, raw: RawDocument) -> ParseResult:
        """Pure function: bytes in, typed facts out. No network, no database."""
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

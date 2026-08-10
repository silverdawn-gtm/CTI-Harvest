from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from crawler.core.models import DiscoveredItem, ParseResult, RawDocument

if TYPE_CHECKING:
    # Type-only: importing Fetcher at runtime would cycle back through core.ratelimit.
    from crawler.core.fetch import Fetcher


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

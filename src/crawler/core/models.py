import hashlib
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class DiscoveredItem:
    """A URL a source wants fetched, plus anything the source already knows about it."""

    url: str
    source: str
    published_at: datetime | None = None
    title: str | None = None
    hint: dict = field(default_factory=dict)

    @property
    def url_hash(self) -> str:
        return hashlib.sha256(self.url.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RawDocument:
    """Bytes as fetched, before any parsing."""

    item: DiscoveredItem
    content: bytes
    content_type: str
    http_status: int
    fetched_at: datetime
    etag: str | None = None
    last_modified: str | None = None

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class VulnerabilityFact:
    """A CVE-level fact asserted by a source."""

    cve_id: str
    vendor: str | None = None
    product: str | None = None
    description: str | None = None
    kev_listed: bool = False
    kev_added_date: datetime | None = None
    published: datetime | None = None


@dataclass(frozen=True)
class ParsedDoc:
    """One logical document extracted from a raw fetch."""

    url: str
    source: str
    title: str
    body_text: str
    license: str
    published_at: datetime | None = None
    vulnerabilities: tuple[VulnerabilityFact, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def url_hash(self) -> str:
        return hashlib.sha256(self.url.encode("utf-8")).hexdigest()

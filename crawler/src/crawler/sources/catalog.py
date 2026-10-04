"""Typed view of config/sources.yaml.

Each entry names an adapter, and the adapter's own flags are checked against that adapter's
model. A typo in the file therefore fails when the crawler starts, not halfway through a crawl.
"""

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from crawler.core.models import RateLimit


class CatalogError(ValueError):
    """config/sources.yaml is missing, malformed, or describes an invalid source."""


class RateLimitConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requests: int = Field(ge=1)
    per_seconds: float = Field(gt=0)

    def to_rate_limit(self) -> RateLimit:
        return RateLimit(requests=self.requests, per_seconds=self.per_seconds)


class _SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    entry_url: str = Field(pattern=r"^https?://\S+$")
    rate_limit: RateLimitConfig = RateLimitConfig(requests=1, per_seconds=2.0)
    license: str = Field(default="copyrighted", min_length=1, max_length=32)
    enabled: bool = True


class RssConfig(_SourceConfig):
    adapter: Literal["rss"]


class SitemapConfig(_SourceConfig):
    adapter: Literal["sitemap"]
    child_pattern: str = Field(min_length=1)
    article_pattern: str = ""


class WordPressConfig(_SourceConfig):
    adapter: Literal["wordpress"]


class KevConfig(_SourceConfig):
    adapter: Literal["kev"]
    license: str = Field(default="public-domain", min_length=1, max_length=32)


class NvdConfig(_SourceConfig):
    adapter: Literal["nvd"]
    license: str = Field(default="public-domain", min_length=1, max_length=32)


SourceConfig = Annotated[
    RssConfig | SitemapConfig | WordPressConfig | KevConfig | NvdConfig,
    Field(discriminator="adapter"),
]


class _CatalogFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[SourceConfig]

    @model_validator(mode="after")
    def _unique_names(self) -> "_CatalogFile":
        seen: set[str] = set()
        for source in self.sources:
            if source.name in seen:
                raise ValueError(f"duplicate source name {source.name!r}")
            seen.add(source.name)
        return self


def load_catalog(path: Path) -> list[SourceConfig]:
    """Every source in `path`, in file order, disabled ones included."""
    path = Path(path)
    try:
        # utf-8-sig: PowerShell 5.1 saves UTF-8 with a byte-order mark.
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise CatalogError(f"{path}: file not found") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"{path}: not valid YAML ({exc})") from exc

    try:
        return _CatalogFile.model_validate(data).sources
    except ValidationError as exc:
        raise CatalogError(f"{path}: {exc}") from exc

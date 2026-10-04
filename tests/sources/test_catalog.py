from pathlib import Path

import pytest
import yaml

from crawler.core.models import RateLimit
from crawler.sources.catalog import (
    CatalogError,
    KevConfig,
    NvdConfig,
    RssConfig,
    SitemapConfig,
    WordPressConfig,
    load_catalog,
)

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "sources.yaml"

EXPECTED = {
    "bleepingcomputer": RssConfig,
    "securityweek": RssConfig,
    "projectzero": RssConfig,
    "krebsonsecurity": SitemapConfig,
    "thehackernews": SitemapConfig,
    "therecord": SitemapConfig,
    "talos": SitemapConfig,
    "sentinelone": SitemapConfig,
    "unit42": WordPressConfig,
    "microsoft": WordPressConfig,
    "malwarebytes": WordPressConfig,
    "kev": KevConfig,
    "nvd": NvdConfig,
}

RSS = {"name": "s", "adapter": "rss", "entry_url": "https://e.org/feed"}


def catalog(*entries: dict) -> str:
    return yaml.safe_dump({"sources": list(entries)})


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "sources.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_shipped_catalog_lists_every_source_with_its_adapter():
    assert {s.name: type(s) for s in load_catalog(SHIPPED)} == EXPECTED


def test_shipped_catalog_preserves_the_hardcoded_settings():
    by_name = {s.name: s for s in load_catalog(SHIPPED)}

    assert by_name["bleepingcomputer"].rate_limit.to_rate_limit() == RateLimit(1, 3.0)
    assert by_name["nvd"].rate_limit.to_rate_limit() == RateLimit(1, 6.5)
    assert by_name["kev"].license == "public-domain"
    assert by_name["krebsonsecurity"].child_pattern == "posts-post"
    assert by_name["thehackernews"].child_pattern == "sitemap.xml?page="
    assert by_name["malwarebytes"].entry_url == "https://www.malwarebytes.com/wp-json/wp/v2/posts"
    assert all(s.enabled for s in by_name.values())


def test_adapter_specific_flags_and_defaults(tmp_path):
    entry = {
        "name": "site",
        "adapter": "sitemap",
        "entry_url": "https://example.org/sitemap.xml",
        "child_pattern": "post-sitemap",
        "article_pattern": "/blog/",
    }
    [site] = load_catalog(write(tmp_path, catalog(entry)))

    assert isinstance(site, SitemapConfig)
    assert (site.child_pattern, site.article_pattern) == ("post-sitemap", "/blog/")
    assert site.enabled is True
    assert site.license == "copyrighted"
    assert site.rate_limit.to_rate_limit() == RateLimit(1, 2.0)


def test_kev_and_nvd_default_to_public_domain(tmp_path):
    path = write(
        tmp_path,
        catalog(
            {"name": "k", "adapter": "kev", "entry_url": "https://e.org/kev.json"},
            {"name": "n", "adapter": "nvd", "entry_url": "https://e.org/nvd"},
        ),
    )
    assert [s.license for s in load_catalog(path)] == ["public-domain", "public-domain"]


@pytest.mark.parametrize(
    "body, message",
    [
        (catalog({**RSS, "adapter": "sitemap"}), "child_pattern"),
        (catalog({**RSS, "adapter": "gopher"}), "adapter"),
        (catalog({**RSS, "child_patern": "x"}), "child_patern"),
        (catalog({**RSS, "entry_url": "ftp://e.org/"}), "entry_url"),
        (catalog({**RSS, "name": "Has Spaces"}), "name"),
        (catalog({**RSS, "rate_limit": {"requests": 0, "per_seconds": 1}}), "requests"),
        (catalog(RSS, {**RSS, "entry_url": "https://e.org/other"}), "duplicate source name 's'"),
        ("", "dictionary"),
        ("sources: [\n", "not valid YAML"),
    ],
)
def test_invalid_catalogs_fail_loudly(tmp_path, body, message):
    with pytest.raises(CatalogError, match=message):
        load_catalog(write(tmp_path, body))


def test_missing_file_names_the_path(tmp_path):
    with pytest.raises(CatalogError, match="not found"):
        load_catalog(tmp_path / "nope.yaml")

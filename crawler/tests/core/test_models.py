from datetime import datetime, timezone

from crawler.core.models import DiscoveredItem, RawDocument


def test_url_hash_is_stable_and_unique():
    a = DiscoveredItem(url="https://example.org/a", source="kev")
    b = DiscoveredItem(url="https://example.org/a", source="kev")
    c = DiscoveredItem(url="https://example.org/b", source="kev")

    assert a.url_hash == b.url_hash
    assert a.url_hash != c.url_hash
    assert len(a.url_hash) == 64


def test_content_hash_detects_change():
    item = DiscoveredItem(url="https://example.org/a", source="kev")
    common = dict(
        item=item,
        content_type="application/json",
        http_status=200,
        fetched_at=datetime.now(timezone.utc),
    )

    same_a = RawDocument(content=b"hello", **common)
    same_b = RawDocument(content=b"hello", **common)
    different = RawDocument(content=b"goodbye", **common)

    assert same_a.content_hash == same_b.content_hash
    assert same_a.content_hash != different.content_hash

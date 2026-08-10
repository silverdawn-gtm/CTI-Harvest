from datetime import datetime, timezone

from crawler.core.models import DiscoveredItem, RawDocument
from crawler.sources.news_rss import NewsRssSource

SOURCE = NewsRssSource("example", "https://example.org/feed/")
WHEN = datetime(2026, 8, 1, tzinfo=timezone.utc)

_PARAGRAPHS = "".join(
    f"<p>Ransomware operators exploited CVE-2026-{1000 + i} to move laterally through the "
    f"victim network before deploying the encryptor on domain controllers, according to "
    f"incident responders who investigated the intrusion in stage {i}.</p>"
    for i in range(12)
)
ARTICLE = f"<html><body><article>{_PARAGRAPHS}</article></body></html>".encode()
THIN = b"<html><body><p>Loading...</p></body></html>"


def make_raw(html: bytes, summary: str = "", title: str | None = "A Title") -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(
            url="https://example.org/a",
            source="example",
            title=title,
            published_at=WHEN,
            hint={"summary": summary},
        ),
        content=html,
        content_type="text/html",
        http_status=200,
        fetched_at=WHEN,
    )


def test_extracts_article_body():
    docs = SOURCE.parse(make_raw(ARTICLE))

    assert len(docs) == 1
    assert "Ransomware operators exploited" in docs[0].body_text
    assert docs[0].published_at == WHEN
    assert docs[0].license == "copyrighted"
    assert docs[0].warnings == ()


def test_thin_page_falls_back_to_feed_summary():
    docs = SOURCE.parse(make_raw(THIN, summary="Feed summary standing in for the article."))

    assert docs[0].body_text == "Feed summary standing in for the article."
    assert any("fell back" in w for w in docs[0].warnings)


def test_missing_title_is_flagged_not_fatal():
    docs = SOURCE.parse(make_raw(ARTICLE, title=None))

    assert docs[0].title == "(untitled)"
    assert any("no title" in w for w in docs[0].warnings)

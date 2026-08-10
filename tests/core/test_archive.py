from datetime import datetime, timezone

from crawler.core.archive import RawArchive
from crawler.core.models import DiscoveredItem, RawDocument


def make_raw(content: bytes, content_type: str) -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(url="https://example.org/a", source="kev"),
        content=content,
        content_type=content_type,
        http_status=200,
        fetched_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )


def test_store_then_load_round_trips(tmp_path):
    archive = RawArchive(tmp_path)
    raw = make_raw(b'{"a": 1}', "application/json")

    path = archive.store(raw)

    assert archive.load(path) == b'{"a": 1}'


def test_path_is_partitioned_by_source_and_date(tmp_path):
    archive = RawArchive(tmp_path)

    path = archive.store(make_raw(b"x", "text/html; charset=utf-8"))

    assert path.startswith("kev/2026/03/")
    assert path.endswith(".html.gz")


def test_extension_follows_content_type(tmp_path):
    archive = RawArchive(tmp_path)

    assert archive.store(make_raw(b"x", "application/json")).endswith(".json.gz")
    assert archive.store(make_raw(b"y", "application/pdf")).endswith(".pdf.gz")
    assert archive.store(make_raw(b"z", "application/octet-stream")).endswith(".bin.gz")


def test_storing_twice_is_idempotent(tmp_path):
    archive = RawArchive(tmp_path)
    raw = make_raw(b"same", "text/html")

    assert archive.store(raw) == archive.store(raw)

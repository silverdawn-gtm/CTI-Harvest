from datetime import datetime, timezone

from crawler.db.schema import Document, Source
from crawler.extraction.runner import load_pending, output_path

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def add(session, n: int, source: str, body: str | None) -> Document:
    doc = Document(
        source=source,
        url=f"https://e.org/{n}",
        url_hash=f"{n:064x}",
        title=f"T{n}",
        body_text=body,
        fetched_at=NOW,
        license="copyrighted",
    )
    session.add(doc)
    session.flush()
    return doc


def test_load_pending_selects_unextracted_documents_with_text(db_session, tmp_path):
    db_session.add_all(
        [Source(name="s1", kind="feed", license="c"), Source(name="s2", kind="feed", license="c")]
    )
    db_session.flush()
    done = add(db_session, 1, "s1", "already extracted")
    empty = add(db_session, 2, "s1", "")
    null = add(db_session, 3, "s1", None)
    todo = add(db_session, 4, "s1", "APT28 used X-Agent.")
    other = add(db_session, 5, "s2", "Lazarus used PlugX.")
    output_path(tmp_path, done.url_hash).write_text("{}", encoding="utf-8")

    rows = load_pending(db_session, tmp_path, None, limit=10, force=False)
    assert [r.id for r in rows] == [todo.id, other.id]
    assert rows[0].body_text == "APT28 used X-Agent." and rows[0].source == "s1"

    assert [r.id for r in load_pending(db_session, tmp_path, ["s2"], 10, False)] == [other.id]
    assert [r.id for r in load_pending(db_session, tmp_path, None, 1, False)] == [todo.id]
    forced = load_pending(db_session, tmp_path, None, 10, True)
    assert [r.id for r in forced] == [done.id, todo.id, other.id]
    assert empty.id not in {r.id for r in forced} and null.id not in {r.id for r in forced}

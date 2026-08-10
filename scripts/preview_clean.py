"""Show a sample of what `crawler clean --apply` would delete, so it can be eyeballed first."""

from sqlalchemy import and_, func, or_, select

from crawler.cli import JUNK_PATH_MARKERS, MIN_ARTICLE_CHARS
from crawler.db.schema import Document
from crawler.db.session import session_scope

with session_scope() as s:
    news = Document.source != "kev"
    junk_url = or_(*(Document.url.contains(m) for m in JUNK_PATH_MARKERS))
    short = func.length(func.coalesce(Document.body_text, "")) < MIN_ARTICLE_CHARS

    rows = s.execute(
        select(Document.source, Document.url, func.length(Document.body_text))
        .where(and_(news, or_(junk_url, short)))
        .order_by(Document.source, Document.url)
    ).all()

    print(f"{len(rows)} rows matched by path/length rules\n")
    by_source: dict[str, int] = {}
    for src, _, _ in rows:
        by_source[src] = by_source.get(src, 0) + 1
    for src, n in sorted(by_source.items(), key=lambda kv: -kv[1]):
        print(f"  {src:<18}{n:>6}")

    print("\n--- sample of 25 ---")
    for src, url, length in rows[:25]:
        print(f"  {src:<16}{length:>6}  {url[:96]}")

    print("\n--- longest 5 flagged (are we losing anything real?) ---")
    for src, url, length in sorted(rows, key=lambda r: -(r[2] or 0))[:5]:
        print(f"  {src:<16}{length:>6}  {url[:96]}")

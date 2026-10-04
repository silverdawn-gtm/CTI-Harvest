"""Profile corpus quality: what would a cleaning pass actually be removing?

Read-only. Run before `crawler clean` to see the shape of the problem.
"""

from datetime import datetime, timezone

from sqlalchemy import Integer, func, select

from crawler.db.schema import Document
from crawler.db.session import session_scope

JUNK_PATHS = ("/tag/", "/tags/", "/author/", "/category/", "/page/", "/topic/")
SHORT = 500


def main() -> None:
    with session_scope() as s:
        total = s.execute(select(func.count(Document.id))).scalar()
        print(f"documents: {total}\n")

        print("=== short bodies (likely index/tag pages, not articles) ===")
        for src, n, short, empty in s.execute(
            select(
                Document.source,
                func.count(Document.id),
                func.sum(func.cast(func.length(Document.body_text) < SHORT, Integer)),
                func.sum(func.cast(func.coalesce(Document.body_text, "") == "", Integer)),
            )
            .group_by(Document.source)
            .order_by(func.count(Document.id).desc())
        ).all():
            flag = "  <-- check" if (short or 0) > 0.05 * n and src != "kev" else ""
            print(f"  {src:<18}{n:>7} docs  short={short or 0:<6} empty={empty or 0}{flag}")

        print("\n=== urls matching junk path patterns ===")
        for pattern in JUNK_PATHS:
            rows = s.execute(
                select(Document.source, func.count(Document.id))
                .where(Document.url.contains(pattern), Document.source != "kev")
                .group_by(Document.source)
            ).all()
            if rows:
                detail = ", ".join(f"{src}={n}" for src, n in rows)
                print(f"  {pattern:<12} {detail}")

        # NOT content_hash: that is the hash of the raw fetch, and one WordPress page or KEV
        # catalog yields hundreds of documents that all share it. Hash the body instead.
        print("\n=== duplicate article text (same body, different url) ===")
        body_md5 = func.md5(Document.body_text)
        dupes = s.execute(
            select(body_md5, func.count(Document.id).label("n"))
            .where(Document.source != "kev", func.length(Document.body_text) > 0)
            .group_by(body_md5)
            .having(func.count(Document.id) > 1)
            .order_by(func.count(Document.id).desc())
            .limit(20)
        ).all()
        extra = sum(n - 1 for _, n in dupes)
        print(f"  {len(dupes)} duplicated bodies, {extra} redundant copies among them")
        for h, n in dupes[:5]:
            url = s.execute(select(Document.url).where(body_md5 == h).limit(1)).scalar()
            print(f"    {n}x  {url[:88]}")

        print("\n=== missing metadata ===")
        no_date = s.execute(
            select(func.count()).where(Document.published_at.is_(None), Document.source != "kev")
        ).scalar()
        no_title = s.execute(
            select(func.count()).where(
                func.coalesce(Document.title, "") == "", Document.source != "kev"
            )
        ).scalar()
        untitled = s.execute(
            select(func.count()).where(Document.title == "(untitled)")
        ).scalar()
        print(f"  no published_at : {no_date}")
        print(f"  no title        : {no_title}")
        print(f"  '(untitled)'    : {untitled}")

        print("\n=== outside the two-year window ===")
        old = s.execute(
            select(Document.source, func.count(Document.id))
            .where(Document.published_at < datetime(2024, 8, 10, tzinfo=timezone.utc))
            .group_by(Document.source)
        ).all()
        for src, n in old:
            print(f"  {src:<18}{n:>7}")


if __name__ == "__main__":
    main()

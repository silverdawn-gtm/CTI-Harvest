from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from crawler.db.schema import Document, Source


def test_database_tests_are_actually_running(db_session):
    """Guards against TEST_DATABASE_URL being unset and every db test skipping unnoticed."""
    assert db_session.execute(text("SELECT 1")).scalar() == 1


def test_document_round_trips(db_session):
    db_session.add(Source(name="kev", kind="api", license="public-domain"))
    db_session.flush()

    doc = Document(
        source="kev",
        url="https://example.org/a",
        url_hash="hash-a",
        title="Example",
        body_text="body",
        fetched_at=datetime.now(timezone.utc),
        license="public-domain",
    )
    db_session.add(doc)
    db_session.flush()

    loaded = db_session.execute(select(Document).where(Document.url_hash == "hash-a")).scalar_one()
    assert loaded.title == "Example"
    assert loaded.fetched_at.tzinfo is not None


def test_url_hash_is_unique(db_session):
    db_session.add(Source(name="kev", kind="api", license="public-domain"))
    db_session.flush()

    for _ in range(2):
        db_session.add(
            Document(
                source="kev",
                url="https://example.org/dup",
                url_hash="same-hash",
                fetched_at=datetime.now(timezone.utc),
                license="public-domain",
            )
        )

    with pytest.raises(IntegrityError):
        db_session.flush()

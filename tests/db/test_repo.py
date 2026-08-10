from datetime import datetime, timezone

from sqlalchemy import select

from crawler.core.models import DiscoveredItem, ParsedDoc, RawDocument, VulnerabilityFact
from crawler.db import repo
from crawler.db.schema import Document, FetchError, Vulnerability

NOW = datetime(2026, 3, 15, tzinfo=timezone.utc)


def make_parsed(url: str = "https://example.org/a", title: str = "T") -> ParsedDoc:
    return ParsedDoc(url=url, source="kev", title=title, body_text="body", license="public-domain")


def make_raw(url: str = "https://example.org/a", content: bytes = b"x") -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(url=url, source="kev"),
        content=content,
        content_type="application/json",
        http_status=200,
        fetched_at=NOW,
        etag='W/"v1"',
    )


def test_upsert_document_inserts_then_updates(db_session):
    repo.ensure_source(db_session, "kev", "api", "public-domain")

    doc, created = repo.upsert_document(db_session, make_parsed(), make_raw(), "kev/p.json.gz")
    db_session.flush()
    assert created is True
    assert doc.title == "T"

    doc2, created2 = repo.upsert_document(
        db_session, make_parsed(title="Updated"), make_raw(content=b"y"), "kev/p2.json.gz"
    )
    db_session.flush()

    assert created2 is False
    assert doc2.id == doc.id
    assert doc2.title == "Updated"
    assert len(db_session.execute(select(Document)).scalars().all()) == 1


def test_upsert_vulnerability_merges_fields(db_session):
    repo.upsert_vulnerability(db_session, VulnerabilityFact(cve_id="CVE-2024-0001", vendor="Acme"))
    db_session.flush()
    repo.upsert_vulnerability(
        db_session, VulnerabilityFact(cve_id="CVE-2024-0001", kev_listed=True, product="Widget")
    )
    db_session.flush()

    vuln = db_session.get(Vulnerability, "CVE-2024-0001")
    assert vuln.vendor == "Acme"
    assert vuln.product == "Widget"
    assert vuln.kev_listed is True


def test_record_fetch_error_increments_attempts(db_session):
    repo.record_fetch_error(
        db_session, "kev", "https://example.org/x", "TransientFetchError", "500"
    )
    db_session.flush()
    repo.record_fetch_error(
        db_session, "kev", "https://example.org/x", "TransientFetchError", "500"
    )
    db_session.flush()

    error = db_session.execute(select(FetchError)).scalar_one()
    assert error.attempts == 2


def test_run_lifecycle(db_session):
    repo.ensure_source(db_session, "kev", "api", "public-domain")
    run = repo.start_run(db_session, "kev")
    db_session.flush()
    assert run.status == "running"

    run.discovered = 5
    repo.finish_run(db_session, run, "ok")
    db_session.flush()

    assert run.status == "ok"
    assert run.finished_at is not None

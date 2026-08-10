from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from crawler.core.models import ParsedDoc, RawDocument, VulnerabilityFact
from crawler.db.schema import CrawlRun, Document, FetchError, Source, Vulnerability


def ensure_source(session: Session, name: str, kind: str, license: str) -> Source:
    source = session.get(Source, name)
    if source is None:
        source = Source(name=name, kind=kind, license=license)
        session.add(source)
    return source


def get_document_by_url_hash(session: Session, url_hash: str) -> Document | None:
    return session.execute(
        select(Document).where(Document.url_hash == url_hash)
    ).scalar_one_or_none()


def content_seen(session: Session, source: str, content_hash: str) -> bool:
    """True when this source already stored a document with byte-identical content.

    Keyed on content rather than URL because a single fetched file may yield many documents
    (the KEV catalog is one JSON file holding ~1,200 vulnerabilities). In that shape the
    fetched URL never gets a `documents` row of its own, so a URL-keyed check can never fire.
    """
    return (
        session.execute(
            select(Document.id)
            .where(Document.source == source, Document.content_hash == content_hash)
            .limit(1)
        ).first()
        is not None
    )


def upsert_document(
    session: Session, parsed: ParsedDoc, raw: RawDocument, raw_path: str | None
) -> tuple[Document, bool]:
    existing = get_document_by_url_hash(session, parsed.url_hash)
    created = existing is None
    doc = existing or Document(
        source=parsed.source, url=parsed.url, url_hash=parsed.url_hash, license=parsed.license
    )

    doc.title = parsed.title
    doc.body_text = parsed.body_text
    doc.published_at = parsed.published_at
    doc.fetched_at = raw.fetched_at
    doc.content_hash = raw.content_hash
    doc.http_status = raw.http_status
    doc.etag = raw.etag
    doc.last_modified = raw.last_modified
    doc.raw_path = raw_path

    if created:
        session.add(doc)
    return doc, created


def upsert_vulnerability(session: Session, fact: VulnerabilityFact) -> None:
    vuln = session.get(Vulnerability, fact.cve_id)
    if vuln is None:
        vuln = Vulnerability(cve_id=fact.cve_id)
        session.add(vuln)

    # Only overwrite with values the source actually asserted.
    for field in (
        "vendor",
        "product",
        "description",
        "published",
        "kev_added_date",
        "cvss_v3",
        "cvss_vector",
    ):
        value = getattr(fact, field)
        if value is not None:
            setattr(vuln, field, value)
    if fact.kev_listed:
        vuln.kev_listed = True


def start_run(session: Session, source: str) -> CrawlRun:
    run = CrawlRun(source=source, started_at=datetime.now(timezone.utc), status="running")
    session.add(run)
    return run


def finish_run(session: Session, run: CrawlRun, status: str, note: str | None = None) -> None:
    run.finished_at = datetime.now(timezone.utc)
    run.status = status
    run.note = note


def record_fetch_error(
    session: Session, source: str, url: str, error_class: str, message: str | None
) -> None:
    existing = session.execute(
        select(FetchError).where(FetchError.source == source, FetchError.url == url)
    ).scalar_one_or_none()

    if existing is None:
        session.add(
            FetchError(
                source=source,
                url=url,
                error_class=error_class,
                message=message,
                attempts=1,
                last_attempt_at=datetime.now(timezone.utc),
            )
        )
        return

    existing.attempts += 1
    existing.error_class = error_class
    existing.message = message
    existing.last_attempt_at = datetime.now(timezone.utc)


def mark_source_success(session: Session, name: str, when: datetime) -> None:
    source = session.get(Source, name)
    if source is not None:
        source.last_success_at = when

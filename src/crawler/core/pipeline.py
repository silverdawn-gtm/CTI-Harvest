import logging
from datetime import datetime

from sqlalchemy.orm import Session

from crawler.core.fetch import FetchError
from crawler.db import repo
from crawler.db.schema import CrawlRun

logger = logging.getLogger(__name__)

CIRCUIT_BREAKER_THRESHOLD = 5
COMMIT_EVERY = 50


async def run_source(source, fetcher, archive, session: Session, since: datetime) -> CrawlRun:
    """Discover, fetch, archive, parse, and persist everything one source offers."""
    repo.ensure_source(session, source.name, source.kind, source.license)
    run = repo.start_run(session, source.name)
    session.flush()

    consecutive_failures = 0
    processed_since_commit = 0
    status = "ok"

    async for item in source.discover(since):
        run.discovered += 1

        existing = repo.get_document_by_url_hash(session, item.url_hash)
        etag = existing.etag if existing else None
        last_modified = existing.last_modified if existing else None

        try:
            raw = await fetcher.fetch(item, etag=etag, last_modified=last_modified)
        except FetchError as exc:
            run.failed += 1
            consecutive_failures += 1
            repo.record_fetch_error(session, source.name, item.url, type(exc).__name__, str(exc))
            if consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                status = "circuit_open"
                repo.finish_run(
                    session,
                    run,
                    status,
                    note=f"{consecutive_failures} consecutive failures; source quarantined",
                )
                session.flush()
                return run
            continue

        consecutive_failures = 0

        if raw is None:  # 304 Not Modified
            continue

        # A byte-identical payload teaches us nothing new, so skip archiving and re-parsing.
        # Checked against stored content rather than the fetched URL: multi-document sources
        # yield many documents from one file, and that file's URL has no `documents` row.
        if repo.content_seen(session, source.name, raw.content_hash):
            continue

        run.fetched += 1
        raw_path = archive.store(raw)

        for parsed in source.parse(raw):
            repo.upsert_document(session, parsed, raw, raw_path)
            for fact in parsed.vulnerabilities:
                repo.upsert_vulnerability(session, fact)
            for warning in parsed.warnings:
                logger.warning("parse warning [%s] %s: %s", source.name, parsed.url, warning)
            run.parsed += 1

        processed_since_commit += 1
        if processed_since_commit >= COMMIT_EVERY:
            session.flush()
            processed_since_commit = 0

    repo.finish_run(session, run, status)
    if status == "ok":
        repo.mark_source_success(session, source.name, run.finished_at)
    session.flush()
    return run

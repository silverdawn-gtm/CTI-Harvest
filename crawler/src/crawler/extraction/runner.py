"""Batch extraction: pick documents, run the pipeline, write one JSON file per document.

A file at <out>/<url_hash>.json is what marks a document as extracted; the database is not
touched. Files are written atomically, and a document whose LLM pass failed anywhere is not
written at all, so an interrupted or degraded run is simply resumed by running again.

A failed document gets a sidecar, <out>/<url_hash>.failed.json, counting its failed runs. Later
runs try fresh documents first, and skip one that has failed MAX_FAILED_ATTEMPTS runs (unless
asked to retry them), so a document that always fails cannot hold up the queue.
"""

import asyncio
import json
import os
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from crawler.config import Settings
from crawler.core.models import RateLimit
from crawler.core.ratelimit import DomainRateLimiter
from crawler.db.schema import Document
from crawler.db.session import session_scope
from crawler.extraction.client import build_chat_client
from crawler.extraction.llm import LLMExtractor
from crawler.extraction.ontology import Ontology, load_ontology
from crawler.extraction.pipeline import DocumentExtraction, SentenceExtractor, extract_text
from crawler.extraction.rules import RuleMatcher, load_matcher

# A provider that fails every sentence of this many documents in a row is down, out of quota,
# or rejecting our key or schema. Stop, rather than walk the backlog writing nothing.
MAX_CONSECUTIVE_DEAD_DOCUMENTS = 3
# A document that failed this many runs is skipped unless retried explicitly.
MAX_FAILED_ATTEMPTS = 3


class ExtractionAborted(RuntimeError):
    """The LLM failed every sentence of several documents in a row."""


@dataclass(frozen=True)
class DocumentRow:
    id: int
    url: str
    url_hash: str
    source: str
    title: str | None
    published_at: datetime | None
    body_text: str


@dataclass(frozen=True)
class Summary:
    written: int = 0
    failed: int = 0


def output_path(out_dir: Path, url_hash: str) -> Path:
    return Path(out_dir) / f"{url_hash}.json"


def failed_path(out_dir: Path, url_hash: str) -> Path:
    return Path(out_dir) / f"{url_hash}.failed.json"


def failed_attempts(out_dir: Path, url_hash: str) -> int:
    """Runs this document has failed so far (0 without a readable sidecar)."""
    path = failed_path(out_dir, url_hash)
    if not path.exists():
        return 0
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["attempts"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0


def select_pending(
    candidates: Iterable[tuple[int, str]],
    out_dir: Path,
    limit: int,
    force: bool,
    retry_failed: bool = False,
) -> list[int]:
    """Ids of up to `limit` candidates to extract, in candidate order, fresh ones first.

    A candidate with an output file is skipped (unless force). One with a failure sidecar
    goes after every fresh candidate, and is skipped altogether once it has failed
    MAX_FAILED_ATTEMPTS runs (unless force or retry_failed).
    """
    fresh: list[int] = []
    failed: list[int] = []
    for doc_id, url_hash in candidates:
        if len(fresh) >= limit:
            break
        if not force and output_path(out_dir, url_hash).exists():
            continue
        if not failed_path(out_dir, url_hash).exists():
            fresh.append(doc_id)
        elif len(failed) < limit and (
            force or retry_failed or failed_attempts(out_dir, url_hash) < MAX_FAILED_ATTEMPTS
        ):
            failed.append(doc_id)
    return (fresh + failed)[:limit]


def build_record(
    row: DocumentRow,
    result: DocumentExtraction,
    ontology_version: str,
    llm_model: str | None,
    extracted_at: datetime,
) -> dict[str, Any]:
    return {
        "document_id": row.id,
        "url": row.url,
        "url_hash": row.url_hash,
        "source": row.source,
        "title": row.title,
        "published_at": row.published_at.isoformat() if row.published_at else None,
        "extracted_at": extracted_at.isoformat(),
        "ontology_version": ontology_version,
        "llm_model": llm_model,
        "sentences": result.sentences,
        "entities": [asdict(e) for e in result.entities],
        "relations": [asdict(r) for r in result.relations],
        "warnings": list(result.warnings),
        "dropped": list(result.dropped),
    }


def _write_json(data: dict[str, Any], target: Path) -> Path:
    """Write atomically: a crash mid-write must not leave a partial file at `target`."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".extract-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=1)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def write_record(record: dict[str, Any], out_dir: Path) -> Path:
    """Write atomically: a crash mid-write must not leave a file that reads as extracted."""
    return _write_json(record, output_path(out_dir, record["url_hash"]))


def record_failure(
    out_dir: Path, url_hash: str, warnings: Sequence[str], updated_at: datetime
) -> int:
    """Count one more failed run in the document's sidecar; returns the new count."""
    attempts = failed_attempts(out_dir, url_hash) + 1
    sidecar = {
        "url_hash": url_hash,
        "attempts": attempts,
        "last_warnings": list(warnings),
        "updated_at": updated_at.isoformat(),
    }
    _write_json(sidecar, failed_path(out_dir, url_hash))
    return attempts


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def process(
    rows: Sequence[DocumentRow],
    out_dir: Path,
    matcher: RuleMatcher,
    ontology: Ontology,
    llm: SentenceExtractor | None,
    echo: Callable[[str], None] = print,
    now: Callable[[], datetime] = _utc_now,
) -> Summary:
    written = failed = 0
    # A document whose every sentence failed is charged a failed run only once a later document
    # shows the provider is alive, or the run ends. If its streak ends in an abort, the
    # provider was down and the documents are not to blame.
    dead: list[tuple[DocumentRow, DocumentExtraction]] = []

    def charge(row: DocumentRow, result: DocumentExtraction) -> None:
        attempts = record_failure(out_dir, row.url_hash, result.warnings, now())
        if attempts >= MAX_FAILED_ATTEMPTS:
            echo(
                f"{row.source:<16} {row.url_hash[:12]} has failed {attempts} runs; "
                "skipped from now on unless --retry-failed"
            )

    def charge_dead() -> None:
        for dead_row, dead_result in dead:
            charge(dead_row, dead_result)
        dead.clear()

    for row in rows:
        result = await extract_text(row.body_text, matcher, ontology, llm)
        label = f"{row.source:<16} {row.url_hash[:12]}"

        if result.llm_failures:
            failed += 1
            echo(
                f"{label} FAILED {result.llm_failures}/{result.sentences} sentences: "
                f"{result.warnings[0]}"
            )
            if result.llm_failures < result.sentences:
                charge_dead()
                charge(row, result)
                continue
            dead.append((row, result))
            if len(dead) >= MAX_CONSECUTIVE_DEAD_DOCUMENTS:
                raise ExtractionAborted(
                    f"LLM failed every sentence of {len(dead)} documents in a row; "
                    f"last error: {result.warnings[-1]}"
                )
            continue

        charge_dead()
        record = build_record(
            row, result, ontology.version, getattr(llm, "model_name", None), now()
        )
        write_record(record, out_dir)
        failed_path(out_dir, row.url_hash).unlink(missing_ok=True)
        written += 1
        echo(f"{label} entities={len(result.entities):<4} relations={len(result.relations)}")
    charge_dead()
    return Summary(written, failed)


def load_pending(
    session: Session,
    out_dir: Path,
    sources: Sequence[str] | None,
    limit: int,
    force: bool,
    retry_failed: bool = False,
) -> list[DocumentRow]:
    """Documents with body text and no output file yet, chosen by select_pending, by id.

    Ids and hashes are read first and filtered against the output directory, so only the
    bodies that will actually be extracted are loaded.
    """
    has_text = func.length(func.coalesce(Document.body_text, "")) > 0
    query = select(Document.id, Document.url_hash).where(has_text).order_by(Document.id)
    if sources:
        query = query.where(Document.source.in_(sources))
    candidates = session.execute(query).tuples()
    ids = select_pending(candidates, out_dir, limit, force, retry_failed)
    if not ids:
        return []

    rows = session.execute(
        select(
            Document.id,
            Document.url,
            Document.url_hash,
            Document.source,
            Document.title,
            Document.published_at,
            Document.body_text,
        )
        .where(Document.id.in_(ids))
        .order_by(Document.id)
    ).tuples()
    return [DocumentRow(*row) for row in rows]


async def run(
    settings: Settings,
    sources: Sequence[str] | None,
    limit: int,
    out_dir: Path,
    rules_only: bool,
    force: bool,
    echo: Callable[[str], None],
    retry_failed: bool = False,
) -> Summary:
    ontology = load_ontology(settings.ontology_path)
    matcher = load_matcher()

    async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
        llm: LLMExtractor | None = None
        if not rules_only:
            # Built before the database is touched: a missing key should fail in a second.
            limiter = DomainRateLimiter(
                default=RateLimit(requests=settings.llm_requests_per_minute, per_seconds=60.0)
            )
            chat = build_chat_client(
                settings, client, limiter, asyncio.Semaphore(settings.llm_parallel)
            )
            llm = LLMExtractor(chat, ontology)

        with session_scope() as session:
            rows = load_pending(session, out_dir, sources, limit, force, retry_failed)
        if not rows:
            echo("Nothing to extract.")
            return Summary()

        mode = "rules only" if rules_only else f"{settings.llm_provider} LLM"
        echo(f"Extracting {len(rows)} documents ({mode}) into {out_dir}")
        return await process(rows, out_dir, matcher, ontology, llm, echo)

"""Batch extraction: pick documents, run the pipeline, write one JSON file per document.

A file at <out>/<url_hash>.json is what marks a document as extracted; the database is not
touched. Files are written atomically, and a document whose LLM pass failed anywhere is not
written at all, so an interrupted or degraded run is simply resumed by running again.
"""

import json
import os
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crawler.extraction.ontology import Ontology
from crawler.extraction.pipeline import DocumentExtraction, SentenceExtractor, extract_text
from crawler.extraction.rules import RuleMatcher

# A provider that fails every sentence of this many documents in a row is down, out of quota,
# or rejecting our key or schema. Stop, rather than walk the backlog writing nothing.
MAX_CONSECUTIVE_DEAD_DOCUMENTS = 3


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


def select_pending(
    candidates: Iterable[tuple[int, str]], out_dir: Path, limit: int, force: bool
) -> list[int]:
    """Ids of the first `limit` candidates without an output file (any candidate with force)."""
    chosen: list[int] = []
    for doc_id, url_hash in candidates:
        if len(chosen) >= limit:
            break
        if force or not output_path(out_dir, url_hash).exists():
            chosen.append(doc_id)
    return chosen


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


def write_record(record: dict[str, Any], out_dir: Path) -> Path:
    """Write atomically: a crash mid-write must not leave a file that reads as extracted."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = output_path(out_dir, record["url_hash"])
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".extract-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


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
    written = failed = dead_streak = 0
    for row in rows:
        result = await extract_text(row.body_text, matcher, ontology, llm)
        label = f"{row.source:<16} {row.url_hash[:12]}"

        if result.llm_failures:
            failed += 1
            echo(
                f"{label} FAILED {result.llm_failures}/{result.sentences} sentences: "
                f"{result.warnings[0]}"
            )
            all_failed = result.llm_failures == result.sentences
            dead_streak = dead_streak + 1 if all_failed else 0
            if dead_streak >= MAX_CONSECUTIVE_DEAD_DOCUMENTS:
                raise ExtractionAborted(
                    f"LLM failed every sentence of {dead_streak} documents in a row; "
                    f"last error: {result.warnings[-1]}"
                )
            continue

        dead_streak = 0
        record = build_record(
            row, result, ontology.version, getattr(llm, "model_name", None), now()
        )
        write_record(record, out_dir)
        written += 1
        echo(f"{label} entities={len(result.entities):<4} relations={len(result.relations)}")
    return Summary(written, failed)

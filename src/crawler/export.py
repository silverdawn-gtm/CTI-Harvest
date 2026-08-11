"""Export the corpus to JSONL or Parquet.

Two datasets, because they are shaped differently and get used differently: `documents` is the
text corpus, `vulnerabilities` is the CVE reference table. Both carry `license` so a
redistributable subset can be filtered out downstream -- news and vendor reports are
copyrighted, NVD and KEV are not.

Rows stream in batches; the vulnerability table alone is six figures and does not want to be
materialised in memory.
"""

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from crawler.db.schema import Document, Vulnerability

BATCH = 2000

DOCUMENT_COLUMNS = [
    "id",
    "source",
    "url",
    "title",
    "body_text",
    "published_at",
    "fetched_at",
    "license",
    "content_hash",
    "raw_path",
]

VULNERABILITY_COLUMNS = [
    "cve_id",
    "published",
    "cvss_v3",
    "cvss_vector",
    "epss",
    "kev_listed",
    "kev_added_date",
    "vendor",
    "product",
    "description",
]


def _rows(session: Session, model, columns: list[str], order) -> Iterator[dict]:
    """Deterministic ordering so two exports of unchanged data are byte-identical."""
    statement = select(model).order_by(*order).execution_options(yield_per=BATCH)
    for obj in session.execute(statement).scalars():
        yield {name: getattr(obj, name) for name in columns}


def _schema(name: str):
    """Declared explicitly, never inferred.

    pyarrow infers types per batch, so a batch in which `kev_added_date` happens to be all
    null infers `null` and then fails to match the earlier batch's type. With 117k rows that
    is not a hypothetical.
    """
    import pyarrow as pa

    ts = pa.timestamp("us", tz="UTC")
    if name == "documents":
        return pa.schema(
            [
                ("id", pa.int64()),
                ("source", pa.string()),
                ("url", pa.string()),
                ("title", pa.string()),
                ("body_text", pa.string()),
                ("published_at", ts),
                ("fetched_at", ts),
                ("license", pa.string()),
                ("content_hash", pa.string()),
                ("raw_path", pa.string()),
            ]
        )
    return pa.schema(
        [
            ("cve_id", pa.string()),
            ("published", ts),
            ("cvss_v3", pa.float64()),
            ("cvss_vector", pa.string()),
            ("epss", pa.float64()),
            ("kev_listed", pa.bool_()),
            ("kev_added_date", ts),
            ("vendor", pa.string()),
            ("product", pa.string()),
            ("description", pa.string()),
        ]
    )


def document_rows(session: Session) -> Iterator[dict]:
    return _rows(
        session,
        Document,
        DOCUMENT_COLUMNS,
        (Document.source, Document.published_at, Document.url_hash),
    )


def vulnerability_rows(session: Session) -> Iterator[dict]:
    return _rows(session, Vulnerability, VULNERABILITY_COLUMNS, (Vulnerability.cve_id,))


def _jsonable(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def write_jsonl(rows: Iterator[dict], path: Path) -> int:
    written = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps({k: _jsonable(v) for k, v in row.items()}, ensure_ascii=False) + "\n"
            )
            written += 1
    return written


def write_parquet(rows: Iterator[dict], path: Path, dataset: str) -> int:
    import pyarrow as pa
    import pyarrow.parquet as pq

    schema = _schema(dataset)
    names = [field.name for field in schema]
    written = 0
    batch: list[dict] = []

    with pq.ParquetWriter(path, schema, compression="zstd") as writer:

        def flush(pending: list[dict]) -> None:
            writer.write_table(
                pa.Table.from_pydict(
                    {name: [row[name] for row in pending] for name in names}, schema=schema
                )
            )

        for row in rows:
            batch.append(row)
            written += 1
            if len(batch) >= BATCH:
                flush(batch)
                batch = []
        if batch:
            flush(batch)

    return written

"""Read the exports back and check they match the database."""

import json
from pathlib import Path

import pyarrow.parquet as pq
from sqlalchemy import func, select

from crawler.db.schema import Document, Vulnerability
from crawler.db.session import session_scope

EXPORT = Path("data/export")

with session_scope() as s:
    db_docs = s.execute(select(func.count(Document.id))).scalar()
    db_vulns = s.execute(select(func.count(Vulnerability.cve_id))).scalar()

print("=== parquet ===")
for name, expected in (("documents", db_docs), ("vulnerabilities", db_vulns)):
    table = pq.read_table(EXPORT / f"{name}.parquet")
    ok = "OK" if table.num_rows == expected else f"MISMATCH (db={expected})"
    print(f"  {name:<16}{table.num_rows:>8} rows  {ok}")
    for field in table.schema:
        nulls = table.column(field.name).null_count
        print(f"      {field.name:<16}{str(field.type):<28}nulls={nulls}")

print("\n=== jsonl ===")
for name, expected in (("documents", db_docs), ("vulnerabilities", db_vulns)):
    path = EXPORT / f"{name}.jsonl"
    with path.open(encoding="utf-8") as handle:
        first = json.loads(handle.readline())
        count = 1 + sum(1 for _ in handle)
    ok = "OK" if count == expected else f"MISMATCH (db={expected})"
    print(f"  {name:<16}{count:>8} rows  {ok}")
    print(f"      keys: {list(first)}")

print("\n=== sample document ===")
table = pq.read_table(EXPORT / "documents.parquet").slice(0, 1).to_pylist()[0]
for key in ("id", "source", "url", "title", "published_at", "license"):
    print(f"  {key:<14}{table[key]}")
print(f"  body_text     {table['body_text'][:120]}...")

print("\n=== license split (for redistribution filtering) ===")
docs = pq.read_table(EXPORT / "documents.parquet", columns=["license"]).to_pydict()["license"]
counts: dict[str, int] = {}
for lic in docs:
    counts[lic] = counts.get(lic, 0) + 1
for lic, n in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"  {lic:<20}{n:>7}")

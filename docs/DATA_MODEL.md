# Data model

PostgreSQL, managed by Alembic (`crawler/alembic/`, models in `crawler/src/crawler/db/schema.py`).

| Table | Purpose | Key columns |
|---|---|---|
| `sources` | one row per configured source | `name` (PK), `kind`, `license`, `enabled`, `last_success_at` |
| `documents` | one row per crawled page/entry | `id`, `source` (FK), `url`, `url_hash` (unique), `content_hash`, `title`, `body_text`, `published_at`, `fetched_at`, `raw_path`, `etag`, `last_modified`, `http_status`, `license` |
| `vulnerabilities` | CVE facts from NVD / KEV | `cve_id` (PK), `published`, `cvss_v3`, `cvss_vector`, `epss`, `kev_listed`, `kev_added_date`, `vendor`, `product`, `description` |
| `crawl_runs` | one row per source per run | `source`, `started_at`, `finished_at`, `discovered`, `fetched`, `parsed`, `failed`, `status`, `note` |
| `fetch_errors` | last failure per (source, url) | `source`, `url`, `error_class`, `message`, `attempts`, `last_attempt_at` |
| `records` | reserved for structured extraction results | `document_id` (FK), `primary_attack_type`, `summary`, `confidence`, `extraction_version`, `extracted_by`, `extra` |
| `actors`, `techniques`, `sectors` | reserved lookup tables | |

`crawl_runs.status` values: `running`, `ok`, `circuit_open`, `discover_failed`.

Extraction results are **not** stored in the database; they are written as JSON files (see
[USAGE.md](USAGE.md)). `records`, `actors`, `techniques` and `sectors` exist in the schema but
are not populated by the current pipeline.

Handy queries:

```sql
SELECT source, count(*) FROM documents GROUP BY source ORDER BY 2 DESC;
SELECT source, status, discovered, fetched, failed FROM crawl_runs ORDER BY started_at DESC LIMIT 20;
SELECT cve_id, cvss_v3 FROM vulnerabilities WHERE kev_listed ORDER BY kev_added_date DESC LIMIT 20;
```

# Structured Feeds: NVD and MITRE ATT&CK — Design

**Date:** 2026-08-10
**Status:** Approved
**Follows:** `2026-08-09-cyber-threat-crawler-design.md` (overall design), Plan 1 (crawler foundation, merged)

## Purpose

Add the two structured reference sources — NVD and MITRE ATT&CK — and generalize the source
contract so adapters can emit facts and entities, not only documents.

This is the first of three remaining phases. The foundation plan sketched a single "Plan 2"
covering six adapters plus the whole rule-based extraction layer. That is two unrelated
subsystems with different shapes, different test strategies, and a clean interface between them
(`documents.body_text` in, junction rows out). They are split instead:

| Phase | Scope |
|---|---|
| **This spec** | Contract refactor, NVD, MITRE ATT&CK, pipeline/CLI wiring |
| Next | Unstructured sources: news RSS, CISA advisories, vendor PDFs |
| Then | Rule-based extraction, plus abuse.ch (see [Deferred](#deferred)) |

ATT&CK comes first because extraction depends on it: the spec generates actor and technique
dictionaries from the STIX bundle rather than hand-maintaining them, so the bundle must be
ingested before actor or technique matching can be built or tested against real data.

## The controlling problem

**None of this phase's sources produce documents.** NVD produces vulnerability facts, ATT&CK
produces actor and technique entities. But Plan 1's contract is `parse(raw) -> list[ParsedDoc]`
and `run_source` persists documents, with vulnerabilities smuggled inside each `ParsedDoc`.
That contract cannot express "this fetch yielded 2,000 CVE facts and no documents".

Three options were considered:

| Option | Trade-off |
|---|---|
| **A. Generalize the return type** | One contract, one pipeline. Edits working Plan 1 code. |
| B. Add a second `harvest()` method | Plan 1 untouched; protocol becomes bimodal and every future adapter author must ask which half they are writing. |
| C. Separate reference-ingest pipeline | Clean separation; duplicates the circuit breaker, `crawl_runs` bookkeeping, and dedup. |

**Option A is chosen.** The bimodality in B and C is accidental rather than essential: every
source does the same thing — fetch bytes, turn them into typed facts, persist. Only the *mix* of
facts differs.

## Contract

`core/models.py` gains `ParseResult`, and `Source.parse` returns it instead of `list[ParsedDoc]`:

```python
@dataclass(frozen=True)
class ParseResult:
    documents:       tuple[ParsedDoc, ...] = ()
    vulnerabilities: tuple[VulnerabilityFact, ...] = ()
    actors:          tuple[ActorFact, ...] = ()
    techniques:      tuple[TechniqueFact, ...] = ()
    iocs:            tuple[IocFact, ...] = ()
    warnings:        tuple[str, ...] = ()
```

`run_source` persists whichever collections are populated. `CrawlRun.parsed` counts persisted
units across all collections rather than documents alone — that is, the sum of documents,
vulnerability facts, actors, techniques, and IOCs written by one `ParseResult`.

`vulnerabilities` moves out of `ParsedDoc` to the top level, and `ParsedDoc` gains
`cve_ids: tuple[str, ...]`. The pipeline writes `document_cves` from that field. Facts then live
in exactly one place, the document↔CVE link survives, and nothing is duplicated. KEV returns
1,662 documents (each carrying one `cve_id`) plus 1,662 facts in a single `ParseResult`; NVD
returns facts and no documents.

New fact types sit alongside `VulnerabilityFact` as frozen dataclasses, with matching `repo`
upserts:

```python
ActorFact(name: str, aliases: tuple[str, ...] = ())
TechniqueFact(id: str, name: str, tactic: str | None = None)
IocFact(type: str, value: str, document_id: int | None = None)
```

`VulnerabilityFact` gains `cvss_v3: float | None` and `cvss_vector: str | None`. The
`vulnerabilities` table already has both columns, plus `epss`, which stays unpopulated — EPSS is
a separate API and out of scope.

`IocFact` is defined now for contract completeness but nothing emits it in this phase.

### Breaking changes to Plan 1

`KevSource.parse`, `run_source`, `tests/sources/test_kev.py`, `tests/core/test_pipeline.py`, and
`tests/test_end_to_end.py` are all touched. The changes are mechanical, and those existing tests
are the evidence that the refactor preserved behaviour.

### Discovery context

Discovery needs more than a date. Rather than growing the signature to
`discover(since, fetcher, mode)`, it takes one argument:

```python
@dataclass(frozen=True)
class DiscoveryContext:
    since: datetime
    fetcher: Fetcher
    mode: Literal["incremental", "backfill"] = "incremental"

async def discover(self, ctx: DiscoveryContext) -> AsyncIterator[DiscoveredItem]: ...
```

`KevSource` ignores the context entirely. NVD uses all three fields. Future adapters gain new
fields without another signature change.

Passing the fetcher into `discover` does not weaken the architecture's controlling constraint:
sources still never touch the database. It does make discovery network-aware, which the original
spec already intended — *"`discover` is async because it pages through APIs and feeds"* — it was
simply never wired up.

### Import cycle to break first

Typing `DiscoveryContext.fetcher` as `Fetcher` creates a circular import:
`sources.base` → `core.fetch` → `core.ratelimit` → `sources.base`. The cycle exists because
`RateLimit` currently lives in `sources/base.py` while `core/ratelimit.py` imports it.

`RateLimit` moves to `core/models.py`, where it belongs — it is a core value type, not a source
concept. `core/ratelimit.py` then imports it from there and the cycle disappears. `sources/base`
re-exports `RateLimit` so the five existing test modules that import it from there keep working.
This move is the first step of the refactor task, before anything else compiles.

## NVD

Endpoint `https://services.nvd.nist.gov/rest/json/cves/2.0`, paged by `startIndex` /
`resultsPerPage` (max 2,000), windowed by `pubStartDate`/`pubEndDate` or
`lastModStartDate`/`lastModEndDate`. NVD caps a date range at 120 days.

### Pagination

Page count is only knowable from a response — `totalResults` arrives in the payload — but
`discover` must yield URLs before anything is fetched. NVD therefore probes with
`resultsPerPage=1`, reads `totalResults`, and yields one `DiscoveredItem` per page. The probe is
nearly free and the result is correct by construction.

Because NVD also caps a date range at 120 days, discovery is two nested loops, not one:

1. Split `[since, now]` into windows of at most 120 days.
2. For each window, probe for `totalResults`, then yield `ceil(totalResults / 2000)` page items
   carrying that window's date parameters and their own `startIndex`.

A window returning zero results yields nothing and costs one probe. For a 2-year backfill that is
roughly 7 window probes and 25 page fetches.

The alternative — fixed windows sized to stay under 2,000 results, with no probe — was rejected
because it silently under-collects whenever CVE volume spikes.

### Backfill vs. incremental

These are genuinely different queries, which is what `ctx.mode` exists to distinguish:

- **backfill** wants CVEs *published* in a window → `pubStartDate` / `pubEndDate`
- **incremental** wants CVEs *modified* since the last success → `lastModStartDate` / `lastModEndDate`

A `lastMod` query would miss CVEs published two years ago and never touched since, so an
incremental run cannot substitute for a backfill.

### Field mapping

`cve_id`, `published`, and the English `description` map directly. `cvss_v3` and `cvss_vector`
come from `metrics.cvssMetricV31[0].cvssData`. Vendor and product come from the first CPE match
in `configurations`, which is imprecise — NVD's real value here is CVSS, description, and dates.

### Merge safety

NVD must not clobber KEV. `repo.upsert_vulnerability` already writes only non-`None` fields and
only ever sets `kev_listed` to `True`, so the two sources merge into one row in either arrival
order. This was verified against the existing implementation, not assumed.

### Rate limiting

50 requests/30s when `NVD_API_KEY` is set, 5/30s when it is not. `Settings` gains
`nvd_api_key: str | None`, and `.env.example` documents it.

## MITRE ATT&CK

One large STIX 2.1 bundle:
`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
(~35 MB). `discover` yields one URL; `parse` walks the bundle once and emits:

- `intrusion-set` → `ActorFact(name, aliases)`. This is the payoff: the bundle carries canonical
  aliases, so `APT29` / `Cozy Bear` / `Midnight Blizzard` / `UNC2452` collapse to one entity
  instead of four. Without this, actor counts are meaningless.
- `attack-pattern` → `TechniqueFact(id, name, tactic)`, taking the `Txxxx` ID from
  `external_references` (where `source_name == "mitre-attack"`) and the tactic from
  `kill_chain_phases`. Sub-techniques (`T1566.001`) fit the existing `String(16)` key.

Objects flagged `revoked` or `x_mitre_deprecated` are skipped. Retired groups and techniques
would otherwise become permanent false-positive sources for every future extraction run.

## Pipeline and operations

Four gaps in Plan 1 that NVD exposes and this phase closes:

1. **`Source.rate_limit` is declared but dead.** `build_fetcher` installs one global default and
   never reads it. Each source's declared limit is now wired into the limiter by host before its
   run.
2. **`crawl` ignores `last_success_at`.** It computes `since` from `--since-days`, so
   "incremental" currently means "re-examine the last 30 days" regardless of what the source
   knows. `crawl` now resumes from `sources.last_success_at`, falling back to the flag on first
   run.
3. **No `backfill` command.** Added as `backfill --since DATE [--source X]`, passing
   `mode="backfill"`.
4. **Discovery cannot make requests.** Addressed by `DiscoveryContext` above.

### Known behaviour: entity-only sources get no dedup

`content_seen` is document-based, so NVD and ATT&CK re-parse their payloads on every run. This is
correct — every upsert is idempotent — just not free. Incremental NVD windows are small enough
that it does not matter in practice.

Raw bytes are still archived for entity-only sources, preserving the ability to reparse without
re-crawling.

## Error handling

Plan 1's machinery covers this phase. NVD's frequent 503s and 429s hit the existing retry path
with `Retry-After` honoured; a page that exhausts retries lands in `fetch_errors` and the run
continues; five consecutive failures quarantine the source with `status='circuit_open'`.
Malformed STIX objects and CVE entries are skipped with a warning rather than aborting a 35 MB
bundle, matching how KEV handles a missing `cveID`.

### Deliberate simplification

The overall spec calls for NVD backfill to resume at the window boundary, implying checkpointing.
With an API key a 2-year backfill is roughly 25 page requests at 50/30s — under a minute — and
every upsert is idempotent, so a crash costs a re-run rather than data. Checkpointing is skipped
and should be revisited only if backfill becomes slow enough to hurt.

## Testing

No network access anywhere in the suite.

New fixtures:

- **NVD page** — a few CVEs, one missing CVSS, one malformed, with a `totalResults` large enough
  to force multi-page math.
- **STIX bundle** — trimmed to one `intrusion-set` with aliases, two `attack-pattern`s including
  a sub-technique, plus one `revoked` and one `x_mitre_deprecated` object that must not appear in
  the output.

The tests that carry the most weight are the ones asserting what a careless implementation gets
wrong:

- pagination yields the correct page count from the probe
- `backfill` and `incremental` select different query parameters
- aliases collapse to a single actor
- revoked and deprecated objects are dropped
- the rate limit changes with `NVD_API_KEY` presence
- NVD does not overwrite KEV's `kev_listed`

Plan 1's KEV, pipeline, and end-to-end tests are updated for `ParseResult` and serve as the
regression evidence for the refactor.

The plan ends with live verification, as Plan 1 did: one real `backfill --source nvd`, one real
`crawl --source attack`, then `stats`.

## To verify during implementation

Two assumptions to check rather than trust:

- Whether `services.nvd.nist.gov` and `raw.githubusercontent.com` disallow the needed paths in
  `robots.txt`. `RobotsDisallowed` would quarantine a source after five URLs.
- That a 35 MB STIX bundle parses in acceptable memory.

## Deferred

**abuse.ch** moves to the extraction phase. ThreatFox is the right feed, but `Ioc.document_id` is
a non-null FK to `documents` and abuse.ch IOCs have no originating document. Storing them needs a
migration making the column nullable, and then `uq_ioc(document_id, type, value)` stops protecting
those rows, because Postgres treats `NULL`s as distinct in unique constraints — requiring a second
partial unique index for the `document_id IS NULL` case. abuse.ch also now requires a free
`Auth-Key` on its APIs. That work belongs next to regex-extracted IOCs, which have the same shape
and the same schema needs, so the migration gets designed once.

**EPSS** scores. Separate API; the column exists and stays null.

## Out of scope

Everything the overall design already excludes, plus: unstructured sources, the extraction layer,
LLM enrichment, `reparse`, and `export`.

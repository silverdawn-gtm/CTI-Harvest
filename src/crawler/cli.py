import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import typer
from sqlalchemy import and_, create_engine, delete, func, or_, select, text, update

from crawler.config import get_settings
from crawler.core.archive import RawArchive
from crawler.core.fetch import Fetcher, RobotsCache
from crawler.core.pipeline import run_source
from crawler.core.ratelimit import DomainRateLimiter
from crawler.db.schema import Document
from crawler.db.session import session_scope

# Importing the package runs its __init__, which registers every source adapter.
from crawler.sources import base as source_registry

app = typer.Typer(help="Cyber threat intelligence crawler.")
db_app = typer.Typer(help="Database operations.")
app.add_typer(db_app, name="db")
sources_app = typer.Typer(help="Source registry.")
app.add_typer(sources_app, name="sources")


# Rate limiting is per-domain, so running sources side by side is no less polite to any one
# publisher -- it just stops a slow archive from blocking every other site behind it.
MAX_CONCURRENT_SOURCES = 6


async def _run_targets(targets, since, mode: str) -> None:
    settings = get_settings()
    fetcher = build_fetcher()
    archive = RawArchive(settings.raw_archive_dir)
    gate = asyncio.Semaphore(MAX_CONCURRENT_SOURCES)

    async def one(target) -> str:
        async with gate:
            try:
                with session_scope() as session:
                    run = await run_source(
                        target,
                        fetcher,
                        archive,
                        session,
                        since,
                        mode=mode,
                        commit_batches=True,
                    )
                    return (
                        f"{target.name}: discovered={run.discovered} fetched={run.fetched} "
                        f"parsed={run.parsed} failed={run.failed} status={run.status}"
                    )
            except Exception as exc:  # noqa: BLE001 - one source must not sink the others
                return f"{target.name}: ABORTED {type(exc).__name__}: {exc}"

    for done in asyncio.as_completed([one(t) for t in targets]):
        typer.echo(await done)


def _targets(source: str | None):
    """`--source a,b,c` selects several; omitting it selects everything registered."""
    if not source:
        return source_registry.all_sources()
    return [source_registry.get_source(name.strip()) for name in source.split(",") if name.strip()]


def build_fetcher() -> Fetcher:
    settings = get_settings()
    client = httpx.AsyncClient(timeout=settings.request_timeout)
    limiter = DomainRateLimiter(default=source_registry.RateLimit(requests=1, per_seconds=2.0))
    robots = RobotsCache(client=client, user_agent=settings.user_agent)
    return Fetcher(client=client, limiter=limiter, user_agent=settings.user_agent, robots=robots)


@db_app.command("ping")
def db_ping() -> None:
    """Verify the database is reachable."""
    settings = get_settings()
    try:
        engine = create_engine(settings.database_url)
        with engine.connect() as conn:
            version = conn.execute(text("SHOW server_version")).scalar()
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator verbatim
        typer.secho(f"FAILED: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    typer.secho(f"OK: PostgreSQL {version}", fg=typer.colors.GREEN)


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply all pending database migrations."""
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")
    typer.secho("Migrations applied.", fg=typer.colors.GREEN)


@sources_app.command("list")
def sources_list() -> None:
    """Show every registered source."""
    for source in source_registry.all_sources():
        typer.echo(f"{source.name:<16} {source.kind:<6} {source.license}")


@app.command()
def crawl(
    source: str | None = typer.Option(None, help="Comma-separated source names."),
    since_days: int = typer.Option(30, help="Look back this many days."),
) -> None:
    """Fetch new documents from every enabled source."""
    since = datetime.now(timezone.utc) - timedelta(days=since_days)
    targets = _targets(source)

    asyncio.run(_run_targets(targets, since, "incremental"))


@app.command()
def backfill(
    since: str = typer.Option(..., help="Load history from this date, e.g. 2024-08-01."),
    source: str | None = typer.Option(None, help="Comma-separated source names."),
) -> None:
    """Load historical data. Queries by publication date rather than modification date."""
    start = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    targets = _targets(source)

    asyncio.run(_run_targets(targets, start, "backfill"))


# Index, tag, and author pages get into sitemaps alongside real articles. They extract to a
# few hundred characters of navigation chrome and are pure noise in a training corpus.
JUNK_PATH_MARKERS = ("/tag/", "/tags/", "/author/", "/category/", "/page/")
MIN_ARTICLE_CHARS = 500
_URL_DATE = re.compile(r"/(20\d{2})/(\d{2})/")


@app.command()
def clean(
    apply: bool = typer.Option(False, "--apply", help="Delete. Without this it is a dry run."),
) -> None:
    """Remove non-article pages and duplicates, and recover dates the crawl could not store."""
    from crawler.db.schema import Document

    with session_scope() as session:
        # KEV entries are short by nature -- a CVE blurb is not a failed extraction.
        news = Document.source != "kev"

        junk_url = or_(*(Document.url.contains(m) for m in JUNK_PATH_MARKERS))
        short = func.length(func.coalesce(Document.body_text, "")) < MIN_ARTICLE_CHARS

        doomed: set[int] = set()
        for label, condition in (
            ("non-article path", and_(news, junk_url)),
            (f"body under {MIN_ARTICLE_CHARS} chars", and_(news, short)),
        ):
            ids = set(session.execute(select(Document.id).where(condition)).scalars().all())
            typer.echo(f"  {label:<28} {len(ids):>6}")
            doomed |= ids

        # Duplicate *bodies*, not content_hash: content_hash is the hash of the raw fetch, so
        # every document from one WordPress page or the KEV catalog already shares it.
        body_md5 = func.md5(Document.body_text)
        dupe_hashes = (
            select(body_md5)
            .where(news, func.length(func.coalesce(Document.body_text, "")) > 0)
            .group_by(body_md5)
            .having(func.count(Document.id) > 1)
            .subquery()
        )
        keepers = (
            select(func.min(Document.id))
            .where(news, body_md5.in_(select(dupe_hashes.c[0])))
            .group_by(body_md5)
            .subquery()
        )
        dupe_ids = set(
            session.execute(
                select(Document.id).where(
                    news,
                    body_md5.in_(select(dupe_hashes.c[0])),
                    Document.id.notin_(select(keepers.c[0])),
                )
            )
            .scalars()
            .all()
        )
        typer.echo(f"  {'duplicate body (keep first)':<28} {len(dupe_ids):>6}")
        doomed |= dupe_ids

        # Recovery, not deletion: sitemaps without <lastmod> left published_at null, but the
        # date is sitting in the URL path.
        undated = session.execute(
            select(Document.id, Document.url).where(news, Document.published_at.is_(None))
        ).all()
        datable = [
            (doc_id, _URL_DATE.search(url))
            for doc_id, url in undated
            if doc_id not in doomed and _URL_DATE.search(url)
        ]
        typer.echo(f"  {'dates recoverable from url':<28} {len(datable):>6}")

        typer.echo(f"\n  {'TO DELETE':<28} {len(doomed):>6}")

        if not apply:
            typer.secho("\nDry run. Re-run with --apply to make these changes.", fg="yellow")
            return

        for doc_id, match in datable:
            session.execute(
                update(Document)
                .where(Document.id == doc_id)
                .values(
                    published_at=datetime(
                        int(match.group(1)), int(match.group(2)), 1, tzinfo=timezone.utc
                    )
                )
            )
        if doomed:
            session.execute(
                delete(Document).where(Document.id.in_(doomed)).execution_options(
                    synchronize_session=False
                )
            )
        typer.secho(
            f"Deleted {len(doomed)} documents, dated {len(datable)}.", fg=typer.colors.GREEN
        )


@app.command()
def export(
    fmt: str = typer.Option("jsonl", "--format", help="jsonl or parquet."),
    out: str = typer.Option("data/export", "--out", help="Output directory."),
) -> None:
    """Write the corpus to disk: documents.* and vulnerabilities.*."""
    from crawler import export as exporter

    if fmt not in ("jsonl", "parquet"):
        typer.secho(f"Unknown format {fmt!r}; expected jsonl or parquet.", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with session_scope() as session:
        for name, rows in (
            ("documents", exporter.document_rows(session)),
            ("vulnerabilities", exporter.vulnerability_rows(session)),
        ):
            path = out_dir / f"{name}.{fmt}"
            if fmt == "jsonl":
                written = exporter.write_jsonl(rows, path)
            else:
                written = exporter.write_parquet(rows, path, name)
            size = path.stat().st_size / 1_048_576
            typer.echo(f"{name:<16}{written:>8} rows  {size:>8.1f} MB  {path}")


@app.command()
def stats() -> None:
    """Summarize what is in the database."""
    with session_scope() as session:
        rows = session.execute(
            select(Document.source, func.count(Document.id)).group_by(Document.source)
        ).all()
    if not rows:
        typer.echo("No documents yet. Run: crawler crawl")
        return
    for name, count in rows:
        typer.echo(f"{name:<16} {count:>8} documents")

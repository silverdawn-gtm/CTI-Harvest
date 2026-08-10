import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import typer
from sqlalchemy import create_engine, func, select, text

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
    source: str | None = typer.Option(None, help="Only crawl this source."),
    since_days: int = typer.Option(30, help="Look back this many days."),
) -> None:
    """Fetch new documents from every enabled source."""
    settings = get_settings()
    since = datetime.now(timezone.utc) - timedelta(days=since_days)
    targets = [source_registry.get_source(source)] if source else source_registry.all_sources()

    async def _run() -> None:
        fetcher = build_fetcher()
        archive = RawArchive(settings.raw_archive_dir)
        for target in targets:
            with session_scope() as session:
                run = await run_source(target, fetcher, archive, session, since)
                typer.echo(
                    f"{target.name}: discovered={run.discovered} fetched={run.fetched} "
                    f"parsed={run.parsed} failed={run.failed} status={run.status}"
                )

    asyncio.run(_run())


@app.command()
def backfill(
    since: str = typer.Option(..., help="Load history from this date, e.g. 2024-08-01."),
    source: str | None = typer.Option(None, help="Only backfill this source."),
) -> None:
    """Load historical data. Queries by publication date rather than modification date."""
    settings = get_settings()
    start = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    targets = [source_registry.get_source(source)] if source else source_registry.all_sources()

    async def _run() -> None:
        fetcher = build_fetcher()
        archive = RawArchive(settings.raw_archive_dir)
        for target in targets:
            with session_scope() as session:
                run = await run_source(
                    target, fetcher, archive, session, start, mode="backfill"
                )
                typer.echo(
                    f"{target.name}: discovered={run.discovered} fetched={run.fetched} "
                    f"parsed={run.parsed} failed={run.failed} status={run.status}"
                )

    asyncio.run(_run())


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

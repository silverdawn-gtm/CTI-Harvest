import typer
from sqlalchemy import create_engine, text

from crawler.config import get_settings

app = typer.Typer(help="Cyber threat intelligence crawler.")
db_app = typer.Typer(help="Database operations.")
app.add_typer(db_app, name="db")


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

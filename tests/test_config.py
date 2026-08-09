from pathlib import Path

from crawler.config import Settings


def test_settings_read_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5433/crawler")
    monkeypatch.setenv("RAW_ARCHIVE_DIR", str(tmp_path / "raw"))

    settings = Settings()

    assert settings.database_url == "postgresql+psycopg://u:p@localhost:5433/crawler"
    assert settings.raw_archive_dir == Path(tmp_path / "raw")
    assert "crawler" in settings.user_agent.lower()


def test_user_agent_has_contact_info(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5433/crawler")

    settings = Settings()

    assert "+" in settings.user_agent or "@" in settings.user_agent

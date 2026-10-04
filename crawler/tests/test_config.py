from pathlib import Path

import pytest
from pydantic import ValidationError

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


def test_extraction_defaults(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5433/crawler")

    settings = Settings(_env_file=None)

    assert settings.extracted_dir == Path("data/extracted")
    assert settings.extracted_rules_dir == Path("data/extracted-rules")
    assert settings.gemini_fallback_models == "gemini-3.6-flash,gemini-2.5-flash"


@pytest.mark.parametrize("field", ["LLM_PARALLEL", "LLM_REQUESTS_PER_MINUTE"])
def test_llm_concurrency_settings_must_be_positive(monkeypatch, field):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5433/crawler")
    monkeypatch.setenv(field, "0")

    with pytest.raises(ValidationError, match=field.lower()):
        Settings(_env_file=None)

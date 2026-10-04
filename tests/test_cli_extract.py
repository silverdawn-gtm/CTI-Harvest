import json
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from crawler import cli
from crawler.config import get_settings
from crawler.extraction import runner


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x@127.0.0.1:1/none")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@contextmanager
def no_database():
    yield object()


def test_extract_rules_only_writes_files(monkeypatch, tmp_path):
    rows = [
        runner.DocumentRow(
            id=1,
            url="https://e.org/1",
            url_hash="a" * 64,
            source="unit42",
            title="T",
            published_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            body_text="APT28 deployed X-Agent against CVE-2017-11882 in March 2019.",
        )
    ]
    seen = {}

    def fake_load_pending(session, out_dir, sources, limit, force):
        seen.update(sources=sources, limit=limit, force=force, out_dir=out_dir)
        return rows

    monkeypatch.setattr(runner, "session_scope", no_database)
    monkeypatch.setattr(runner, "load_pending", fake_load_pending)

    result = CliRunner().invoke(
        cli.app,
        [
            "extract",
            "--rules-only",
            "--out",
            str(tmp_path),
            "--source",
            "unit42, kev",
            "--limit",
            "5",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == {"sources": ["unit42", "kev"], "limit": 5, "force": False, "out_dir": tmp_path}
    record = json.loads((tmp_path / f"{'a' * 64}.json").read_text(encoding="utf-8"))
    assert {e["type"] for e in record["entities"]} >= {"Vulnerability", "Time"}
    assert "Wrote 1 files" in result.output


def test_missing_api_key_fails_before_the_database(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_PROVIDER", "grok")
    monkeypatch.setenv("GROK_API_KEY", "")

    def must_not_query(*args, **kwargs):
        raise AssertionError("database queried before the key was checked")

    monkeypatch.setattr(runner, "load_pending", must_not_query)

    result = CliRunner().invoke(cli.app, ["extract", "--out", str(tmp_path)])

    assert result.exit_code == 1
    assert "GROK_API_KEY is not set" in result.output


def test_nothing_to_extract(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "session_scope", no_database)
    monkeypatch.setattr(runner, "load_pending", lambda *args: [])

    result = CliRunner().invoke(cli.app, ["extract", "--rules-only", "--out", str(tmp_path)])

    assert result.exit_code == 0
    assert "Nothing to extract." in result.output

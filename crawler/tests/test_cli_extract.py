import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crawler import cli
from crawler.config import get_settings
from crawler.extraction import runner

SHIPPED_SOURCES = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x@127.0.0.1:1/none")
    monkeypatch.setenv("SOURCES_CONFIG", str(SHIPPED_SOURCES))
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

    def fake_load_pending(session, out_dir, sources, limit, force, retry_failed):
        seen.update(
            sources=sources, limit=limit, force=force, out_dir=out_dir, retry_failed=retry_failed
        )
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
    assert seen == {
        "sources": ["unit42", "kev"],
        "limit": 5,
        "force": False,
        "out_dir": tmp_path,
        "retry_failed": False,
    }
    record = json.loads((tmp_path / f"{'a' * 64}.json").read_text(encoding="utf-8"))
    assert {e["type"] for e in record["entities"]} >= {"Vulnerability", "Time"}
    assert "Wrote 1 files" in result.output
    assert "Unknown source" not in result.output


def capture_out_dir(monkeypatch) -> dict:
    seen: dict = {}

    def fake_load_pending(session, out_dir, sources, limit, force, retry_failed):
        seen.update(out_dir=out_dir, retry_failed=retry_failed)
        return []

    async def chat(prompt, schema):  # never called: nothing is pending
        raise AssertionError

    monkeypatch.setattr(runner, "build_chat_client", lambda *args: chat)
    monkeypatch.setattr(runner, "session_scope", no_database)
    monkeypatch.setattr(runner, "load_pending", fake_load_pending)
    return seen


def test_rules_only_output_does_not_mark_documents_done_for_the_llm(monkeypatch, tmp_path):
    llm_dir, rules_dir = tmp_path / "llm", tmp_path / "rules"
    monkeypatch.setenv("EXTRACTED_DIR", str(llm_dir))
    monkeypatch.setenv("EXTRACTED_RULES_DIR", str(rules_dir))
    seen = capture_out_dir(monkeypatch)

    assert CliRunner().invoke(cli.app, ["extract", "--rules-only"]).exit_code == 0
    assert seen["out_dir"] == rules_dir

    assert CliRunner().invoke(cli.app, ["extract"]).exit_code == 0
    assert seen["out_dir"] == llm_dir

    runner.write_record({"url_hash": "a" * 64}, rules_dir)
    assert runner.select_pending([(1, "a" * 64)], llm_dir, limit=5, force=False) == [1]


def test_retry_failed_is_passed_through(monkeypatch, tmp_path):
    seen = capture_out_dir(monkeypatch)

    result = CliRunner().invoke(cli.app, ["extract", "--retry-failed", "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert seen == {"out_dir": tmp_path, "retry_failed": True}


def test_unknown_source_names_are_warned_about(monkeypatch, tmp_path):
    capture_out_dir(monkeypatch)

    result = CliRunner().invoke(
        cli.app, ["extract", "--source", "unit42,nosuch,other", "--out", str(tmp_path)]
    )

    assert result.exit_code == 0, result.output
    assert "Unknown source names: nosuch, other" in result.output
    assert "Nothing to extract." in result.output


def test_help_describes_both_default_output_directories():
    result = CliRunner().invoke(cli.app, ["extract", "--help"], env={"COLUMNS": "300"})

    flat = " ".join(result.output.split())
    assert (
        "Output directory (default: data/extracted, or data/extracted-rules with --rules-only)."
        in flat
    )
    assert "--retry-failed" in flat


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


def test_a_rejected_key_fails_the_run_at_once(monkeypatch, tmp_path):
    from crawler.extraction.client import LLMFatal

    calls = []

    async def rejecting_chat(prompt, schema):
        calls.append(prompt)
        raise LLMFatal("m1: HTTP 401: invalid api key")

    rows = [
        runner.DocumentRow(n, f"https://e.org/{n}", f"{n:064x}", "unit42", None, None, "APT28.")
        for n in range(1, 4)
    ]
    monkeypatch.setattr(runner, "build_chat_client", lambda *args: rejecting_chat)
    monkeypatch.setattr(runner, "session_scope", no_database)
    monkeypatch.setattr(runner, "load_pending", lambda *args: rows)

    result = CliRunner().invoke(cli.app, ["extract", "--out", str(tmp_path)])

    assert result.exit_code == 1, result.output
    assert "FAILED: m1: HTTP 401: invalid api key" in result.output
    assert len(calls) == 1
    assert list(tmp_path.iterdir()) == []

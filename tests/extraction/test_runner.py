import json
from datetime import datetime, timezone

import pytest

from crawler.extraction.client import LLMFatal
from crawler.extraction.pipeline import DocumentExtraction, EntityMention, RelationTriple
from crawler.extraction.rules import RuleMatcher
from crawler.extraction.runner import (
    DocumentRow,
    ExtractionAborted,
    Summary,
    build_record,
    output_path,
    process,
    select_pending,
    write_record,
)

MATCHER = RuleMatcher(
    [
        {"name": "APT28", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
        {"name": "X-Agent", "type": "Malware", "id": "S0161", "case_sensitive": True},
    ]
)
NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)


def row(n: int, body: str = "APT28 used X-Agent.") -> DocumentRow:
    return DocumentRow(
        id=n,
        url=f"https://example.org/{n}",
        url_hash=f"{n:064x}",
        source="unit42",
        title=f"Post {n}",
        published_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        body_text=body,
    )


class FakeLLM:
    model_name = "model-a"

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def extract(self, sentence, known=()):
        if self.fail:
            raise RuntimeError("HTTP 401: bad key")
        return [], [("APT28", "uses", "X-Agent")]


def test_select_pending_skips_existing_output_and_respects_the_limit(tmp_path):
    output_path(tmp_path, "b").write_text("{}", encoding="utf-8")
    candidates = [(1, "a"), (2, "b"), (3, "c"), (4, "d")]

    assert select_pending(candidates, tmp_path, limit=2, force=False) == [1, 3]
    assert select_pending(candidates, tmp_path, limit=10, force=True) == [1, 2, 3, 4]


def test_temp_files_do_not_count_as_extracted(tmp_path):
    (tmp_path / ".extract-123.tmp").write_text("{", encoding="utf-8")
    assert select_pending([(1, "a")], tmp_path, limit=5, force=False) == [1]


def test_build_record_shape():
    result = DocumentExtraction(
        entities=(EntityMention(0, "APT28", "ThreatGroup", 0, 5, 0, "rules"),),
        relations=(RelationTriple(0, "alias-of", 0, 0),),
        sentences=1,
        llm_failures=0,
        dropped=("sentence 0: x",),
    )
    record = build_record(row(7), result, "v1", "model-a", NOW)

    assert record == {
        "document_id": 7,
        "url": "https://example.org/7",
        "url_hash": f"{7:064x}",
        "source": "unit42",
        "title": "Post 7",
        "published_at": "2026-09-01T00:00:00+00:00",
        "extracted_at": "2026-10-04T12:00:00+00:00",
        "ontology_version": "v1",
        "llm_model": "model-a",
        "sentences": 1,
        "entities": [
            {
                "id": 0,
                "text": "APT28",
                "type": "ThreatGroup",
                "start": 0,
                "end": 5,
                "sentence": 0,
                "origin": "rules",
            }
        ],
        "relations": [{"source": 0, "relation": "alias-of", "target": 0, "sentence": 0}],
        "warnings": [],
        "dropped": ["sentence 0: x"],
    }


def test_write_record_round_trips_and_overwrites(tmp_path):
    path = write_record({"url_hash": "abc", "v": 1}, tmp_path / "out")
    write_record({"url_hash": "abc", "v": 2}, tmp_path / "out")

    assert path == tmp_path / "out" / "abc.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {"url_hash": "abc", "v": 2}
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["abc.json"]


def test_failed_write_leaves_no_file(tmp_path):
    with pytest.raises(TypeError):
        write_record({"url_hash": "abc", "bad": object()}, tmp_path)
    assert list(tmp_path.iterdir()) == []


async def test_process_writes_one_file_per_document(tmp_path, ontology):
    lines: list[str] = []

    summary = await process(
        [row(1), row(2)], tmp_path, MATCHER, ontology, FakeLLM(), lines.append, lambda: NOW
    )

    assert summary == Summary(written=2, failed=0)
    record = json.loads(output_path(tmp_path, f"{1:064x}").read_text(encoding="utf-8"))
    assert [e["text"] for e in record["entities"]] == ["APT28", "X-Agent"]
    assert record["relations"] == [{"source": 0, "relation": "uses", "target": 1, "sentence": 0}]
    assert record["llm_model"] == "model-a"
    assert record["ontology_version"] == ontology.version
    assert len(lines) == 2 and "entities=2" in lines[0]


async def test_rules_only_records_no_model(tmp_path, ontology):
    await process([row(1)], tmp_path, MATCHER, ontology, None, lambda line: None, lambda: NOW)
    record = json.loads(output_path(tmp_path, f"{1:064x}").read_text(encoding="utf-8"))
    assert record["llm_model"] is None and record["relations"] == []


async def test_documents_with_llm_failures_are_not_written(tmp_path, ontology):
    lines: list[str] = []

    summary = await process([row(1)], tmp_path, MATCHER, ontology, FakeLLM(fail=True), lines.append)

    assert summary == Summary(written=0, failed=1)
    assert list(tmp_path.iterdir()) == []
    assert "FAILED 1/1 sentences" in lines[0]
    assert select_pending([(1, f"{1:064x}")], tmp_path, limit=5, force=False) == [1]


async def test_three_dead_documents_in_a_row_abort(tmp_path, ontology):
    rows = [row(n) for n in range(1, 6)]

    with pytest.raises(ExtractionAborted, match="3 documents in a row.*bad key"):
        await process(rows, tmp_path, MATCHER, ontology, FakeLLM(fail=True), lambda line: None)
    assert list(tmp_path.iterdir()) == []


async def test_a_partial_failure_does_not_count_toward_the_abort(tmp_path, ontology):
    class Flaky:
        model_name = "m"

        async def extract(self, sentence, known=()):
            if "first" in sentence:
                raise RuntimeError("blip")
            return [], []

    rows = [row(n, "The first one. APT28 used X-Agent.") for n in range(1, 5)]
    summary = await process(rows, tmp_path, MATCHER, ontology, Flaky(), lambda line: None)
    assert summary == Summary(written=0, failed=4)


async def test_a_fatal_llm_error_stops_the_run_at_the_first_document(tmp_path, ontology):
    class Rejecting:
        model_name = "m"
        calls = 0

        async def extract(self, sentence, known=()):
            Rejecting.calls += 1
            raise LLMFatal("m: HTTP 401: bad key")

    rows = [row(n) for n in range(1, 4)]
    with pytest.raises(LLMFatal, match="HTTP 401"):
        await process(rows, tmp_path, MATCHER, ontology, Rejecting(), lambda line: None)
    assert Rejecting.calls == 1
    assert list(tmp_path.iterdir()) == []

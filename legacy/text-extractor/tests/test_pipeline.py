from extractors.rules import RuleMatcher
from pipeline import extract_records

MATCHER = RuleMatcher([
    {"name": "APT28", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
    {"name": "Fancy Bear", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
    {"name": "Germany", "type": "Location", "id": "DE", "case_sensitive": True},
])
EVERYTHING = {"ThreatGroup", "Malware", "Organization", "Location", "Time", "ThreatActor", "Vulnerability"}


class FakeLLM:
    def __init__(self, entities=(), triples=(), fail=False):
        self.entities, self.triples, self.fail = list(entities), list(triples), fail
        self.calls = []

    def extract(self, sentence, entity_types, relation_types=None, known=()):
        self.calls.append({"sentence": sentence, "types": entity_types, "known": known})
        if self.fail:
            raise RuntimeError("429 quota")
        return self.entities, self.triples


def test_merges_rule_and_llm_entities_and_relations():
    llm = FakeLLM([("X-Agent", "Malware"), ("banks", "Organization")],
                  [("APT28", "uses", "X-Agent"), ("APT28", "targets", "banks"), ("APT28", "operates-in", "Germany")])
    records, warnings = extract_records("APT28 used X-Agent against banks in Germany.", llm, MATCHER, EVERYTHING)
    rec = records[0]
    assert rec["text"] == "APT28 used X-Agent against banks in Germany ."
    assert [(e[2], e[3]) for e in rec["entities"]] == [
        ("APT28", "ThreatGroup"), ("X-Agent", "Malware"), ("banks", "Organization"), ("Germany", "Location")]
    assert [r for r in rec["relations"] if r[0] != "noRelation"] == [
        ["uses", 1, 0], ["targets", 2, 0], ["operates-in", 3, 0]]
    assert warnings == []


def test_llm_is_told_what_the_rules_found():
    llm = FakeLLM()
    extract_records("APT28 is back.", llm, MATCHER, EVERYTHING)
    assert [k[2] for k in llm.calls[0]["known"]] == ["APT28"]
    assert llm.calls[0]["sentence"] == "APT28 is back ."


def test_rule_entities_win_over_llm_on_overlap():
    llm = FakeLLM([("APT28", "ThreatActor"), ("APT28 group", "ThreatGroup")])
    records, _ = extract_records("the APT28 group", llm, MATCHER, EVERYTHING)
    assert [(e[2], e[3]) for e in records[0]["entities"]] == [("APT28", "ThreatGroup")]


def test_invalid_relations_are_dropped():
    llm = FakeLLM([("X-Agent", "Malware")], [("X-Agent", "operates-in", "Germany")])
    records, _ = extract_records("X-Agent in Germany", llm, MATCHER, EVERYTHING)
    assert {r[0] for r in records[0]["relations"]} == {"noRelation"}


def test_rule_aliases_are_kept():
    records, _ = extract_records("APT28 , also known as Fancy Bear .", FakeLLM(), MATCHER, EVERYTHING)
    assert records[0]["relations"] == [["alias-of", 1, 0]]


def test_only_selected_types_reach_the_output_and_the_llm():
    llm = FakeLLM([("X-Agent", "Malware")])
    records, _ = extract_records("APT28 used X-Agent in Germany.", llm, MATCHER, {"Malware", "Location"})
    assert [(e[2], e[3]) for e in records[0]["entities"]] == [("X-Agent", "Malware"), ("Germany", "Location")]
    assert llm.calls[0]["types"] == {"Malware", "Location"}


def test_unselected_relations_are_dropped():
    llm = FakeLLM([("X-Agent", "Malware")], [("APT28", "uses", "X-Agent"), ("APT28", "operates-in", "Germany")])
    records, _ = extract_records("APT28 used X-Agent in Germany.", llm, MATCHER, EVERYTHING,
                                 relation_types={"operates-in"})
    assert [r for r in records[0]["relations"] if r[0] != "noRelation"] == [["operates-in", 2, 0]]


def test_llm_failure_falls_back_to_rules_with_a_warning():
    records, warnings = extract_records("APT28 hit Germany. Then more.", FakeLLM(fail=True), MATCHER, EVERYTHING)
    assert [(e[2], e[3]) for e in records[0]["entities"]] == [("APT28", "ThreatGroup"), ("Germany", "Location")]
    assert len(records) == 2
    assert "429 quota" in warnings[0] and "rules only" in warnings[0]


def test_rules_only_mode_without_an_llm():
    records, warnings = extract_records("APT28 hit Germany.", None, MATCHER, EVERYTHING)
    assert len(records[0]["entities"]) == 2 and warnings == []


def test_records_are_well_formed():
    llm = FakeLLM([("X-Agent", "Malware"), ("banks", "Organization")])
    for rec in extract_records("APT28 used X-Agent against banks in Germany in 2019.", llm, MATCHER,
                               EVERYTHING)[0]:
        n = len(rec["entities"])
        assert len(rec["ent_labels"]) == len(rec["text"].split())
        assert len(rec["relations"]) == n * (n - 1) // 2
        assert all(i > j for _, i, j in rec["relations"])


def test_get_llm_extractor_rejects_unknown_provider():
    import pytest
    from pipeline import get_llm_extractor
    with pytest.raises(ValueError):
        get_llm_extractor("nonsense")


def test_get_llm_extractor_builds_mistral_without_calling_the_api(monkeypatch):
    from extractors.llm import SchemaLLMExtractor
    from pipeline import get_llm_extractor
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    get_llm_extractor.cache_clear()
    try:
        assert isinstance(get_llm_extractor("mistral"), SchemaLLMExtractor)
    finally:
        get_llm_extractor.cache_clear()


def test_get_llm_extractor_builds_grok_without_calling_the_api(monkeypatch):
    from extractors.llm import SchemaLLMExtractor
    from pipeline import get_llm_extractor
    monkeypatch.setenv("GROK_API_KEY", "test-key")
    get_llm_extractor.cache_clear()
    try:
        assert isinstance(get_llm_extractor("grok"), SchemaLLMExtractor)
    finally:
        get_llm_extractor.cache_clear()


# --- parallel LLM calls -----------------------------------------------------------------
import threading
import time


class ConcurrencyLLM:
    """Records how many calls run at once; optional per-sentence delay and failure."""

    def __init__(self, delays=None, fail_on=None, barrier=None):
        self.delays, self.fail_on, self.barrier = delays or {}, fail_on, barrier
        self.active = self.peak = 0
        self.lock = threading.Lock()

    def extract(self, sentence, entity_types, relation_types=None, known=()):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.barrier:
                self.barrier.wait()  # only passes if the calls really overlap
            time.sleep(self.delays.get(sentence.split()[0], 0))
            if self.fail_on and self.fail_on in sentence:
                raise RuntimeError("503 overloaded")
            return [("X-Agent", "Malware")], []
        finally:
            with self.lock:
                self.active -= 1


TWO = "APT28 used X-Agent. Lazarus used X-Agent."


def test_llm_calls_for_different_sentences_overlap():
    llm = ConcurrencyLLM(barrier=threading.Barrier(2, timeout=5))
    records, warnings = extract_records(TWO, llm, MATCHER, EVERYTHING, parallel=2)
    assert warnings == []
    assert all(("X-Agent", "Malware") in [(e[2], e[3]) for e in r["entities"]] for r in records)


def test_results_keep_sentence_order_when_calls_finish_out_of_order():
    llm = ConcurrencyLLM(delays={"APT28": 0.3})  # the first sentence finishes last
    records, _ = extract_records(TWO, llm, MATCHER, EVERYTHING, parallel=2)
    assert [r["text"].split()[0] for r in records] == ["APT28", "Lazarus"]


def test_a_failed_sentence_only_affects_itself():
    llm = ConcurrencyLLM(fail_on="Lazarus")
    records, warnings = extract_records(TWO, llm, MATCHER, EVERYTHING, parallel=2)
    assert len(warnings) == 1 and warnings[0].startswith("sentence 2:") and "503 overloaded" in warnings[0]
    assert ("X-Agent", "Malware") in [(e[2], e[3]) for e in records[0]["entities"]]
    assert ("X-Agent", "Malware") not in [(e[2], e[3]) for e in records[1]["entities"]]


def test_parallel_one_runs_calls_one_at_a_time():
    llm = ConcurrencyLLM(delays={"APT28": 0.05, "Lazarus": 0.05})
    extract_records(TWO, llm, MATCHER, EVERYTHING, parallel=1)
    assert llm.peak == 1


def test_parallelism_comes_from_llm_parallel_setting(monkeypatch):
    monkeypatch.setenv("LLM_PARALLEL", "1")
    llm = ConcurrencyLLM(delays={"APT28": 0.05, "Lazarus": 0.05})
    extract_records(TWO, llm, MATCHER, EVERYTHING)
    assert llm.peak == 1


def test_default_parallelism_is_four(monkeypatch):
    monkeypatch.delenv("LLM_PARALLEL", raising=False)
    text = " ".join(f"APT28 used X-Agent {n}." for n in range(4))
    llm = ConcurrencyLLM(barrier=threading.Barrier(4, timeout=5))  # passes only with 4 calls in flight
    records, warnings = extract_records(text, llm, MATCHER, EVERYTHING)
    assert warnings == [] and len(records) == 4 and llm.peak == 4

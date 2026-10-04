import json

import pytest

from extractors.llm import (EXAMPLES_PATH, SchemaLLMExtractor, build_prompt, filter_example,
                            parse_response, response_schema)
from formatter import locate_spans
from ontology import load_base_schema, load_schema
from validator import validate

EVERYTHING = set(load_base_schema().presets["Everything"])


def reply(entities=(), relations=()):
    return json.dumps({
        "entities": [{"text": t, "type": ty} for t, ty in entities],
        "relations": [{"source": s, "relation": r, "target": o} for s, r, o in relations],
    })


# --- examples ---------------------------------------------------------------------------

@pytest.mark.parametrize("example", json.loads(EXAMPLES_PATH.read_text(encoding="utf-8")),
                         ids=lambda e: e["text"][:30])
def test_examples_are_valid_under_the_schema(example):
    spans = locate_spans(example["text"], [(e["text"], e["type"]) for e in example["entities"]])
    assert len(spans) == len(example["entities"]), "every example entity must occur in its text"
    index = {s[2]: n for n, s in enumerate(spans)}
    triples = [(index[r["source"]], r["relation"], index[r["target"]]) for r in example["relations"]]
    _, kept, dropped = validate(spans, triples, EVERYTHING)
    assert dropped == [] and len(kept) == len(triples)


def test_filter_example_keeps_only_selected_types_and_their_relations():
    example = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))[0]
    out = filter_example(example, {"ThreatGroup", "Malware"}, load_schema().relations_for({"ThreatGroup", "Malware"}))
    assert [e["text"] for e in out["entities"]] == ["APT28", "X-Agent"]
    assert out["relations"] == [{"source": "APT28", "relation": "uses", "target": "X-Agent"}]


# --- prompt -----------------------------------------------------------------------------

def test_prompt_lists_only_selected_types_and_possible_relations():
    prompt = build_prompt("APT28 used X-Agent .", {"ThreatGroup", "Malware"})
    assert "ThreatGroup:" in prompt and "Malware:" in prompt
    assert "Vulnerability:" not in prompt
    assert "uses: ThreatGroup -> Malware" in prompt
    assert "targets" not in prompt


def test_prompt_includes_known_entities():
    prompt = build_prompt("APT28 used X-Agent .", {"ThreatGroup", "Malware"},
                          known=[[0, 1, "APT28", "ThreatGroup"]])
    assert '"APT28" (ThreatGroup)' in prompt


def test_prompt_ends_with_the_sentence():
    assert build_prompt("APT28 used X-Agent .", {"Malware"}).rstrip().endswith("APT28 used X-Agent .")


def test_prompt_without_relations_says_so():
    prompt = build_prompt("x .", {"FileHash"})
    assert "Do not output relations" in prompt


def test_response_schema_restricts_labels():
    schema = response_schema({"ThreatGroup", "Malware"}, {"uses": [("ThreatGroup", "Malware")]})
    entity = schema["properties"]["entities"]["items"]["properties"]
    relation = schema["properties"]["relations"]["items"]["properties"]
    assert set(entity["type"]["enum"]) == {"ThreatGroup", "Malware"}
    assert set(relation["relation"]["enum"]) == {"uses", "used-by"}


# --- parsing ----------------------------------------------------------------------------

def test_parse_response_keeps_selected_types_and_known_relations():
    raw = reply([("APT28", "ThreatGroup"), ("X-Agent", "Malware"), ("banks", "Organization")],
                [("APT28", "uses", "X-Agent"), ("APT28", "hates", "X-Agent")])
    entities, triples = parse_response(raw, {"ThreatGroup", "Malware"}, {"uses", "used-by"})
    assert entities == [("APT28", "ThreatGroup"), ("X-Agent", "Malware")]
    assert triples == [("APT28", "uses", "X-Agent")]


def test_parse_response_allows_relations_to_known_entities():
    raw = reply([("X-Agent", "Malware")], [("APT28", "uses", "X-Agent")])
    _, triples = parse_response(raw, {"ThreatGroup", "Malware"}, {"uses"}, known_texts={"APT28"})
    assert triples == [("APT28", "uses", "X-Agent")]


def test_parse_response_drops_relations_to_unlisted_entities():
    raw = reply([("X-Agent", "Malware")], [("APT28", "uses", "X-Agent")])
    assert parse_response(raw, {"ThreatGroup", "Malware"}, {"uses"}) == ([("X-Agent", "Malware")], [])


@pytest.mark.parametrize("raw", ["not json", '{"entities": "x"}', "[]"])
def test_parse_response_rejects_unusable_replies(raw):
    with pytest.raises(ValueError):
        parse_response(raw, {"Malware"}, set())


# --- extractor --------------------------------------------------------------------------

def test_extractor_passes_prompt_and_schema_and_parses():
    calls = []

    def complete(prompt, response_schema=None):
        calls.append((prompt, response_schema))
        return reply([("X-Agent", "Malware")])

    ex = SchemaLLMExtractor(complete)
    assert ex.extract("APT28 used X-Agent .", {"Malware"}) == ([("X-Agent", "Malware")], [])
    assert "X-Agent" in calls[0][0] and calls[0][1]["type"] == "object"


def test_extractor_retries_once_then_gives_up():
    calls = []
    ex = SchemaLLMExtractor(lambda prompt, response_schema=None: calls.append(1) or "oops")
    assert ex.extract("x .", {"Malware"}) == ([], [])
    assert len(calls) == 2


def test_extractor_skips_the_call_when_nothing_is_selected():
    ex = SchemaLLMExtractor(lambda *a, **k: pytest.fail("should not call"))
    assert ex.extract("x .", set()) == ([], [])

import json

import pytest

from crawler.extraction.llm import (
    LLMExtractor,
    build_prompt,
    load_examples,
    parse_response,
    response_schema,
)


def reply(entities=(), relations=()) -> str:
    return json.dumps(
        {
            "entities": [{"text": t, "type": ty} for t, ty in entities],
            "relations": [
                {"source": s, "source_type": st, "relation": r, "target": t, "target_type": tt}
                for s, st, r, t, tt in relations
            ],
        }
    )


def objects(node):
    """Every JSON-Schema object node in `node`."""
    if isinstance(node, dict):
        if node.get("type") == "object":
            yield node
        for value in node.values():
            yield from objects(value)
    elif isinstance(node, list):
        for value in node:
            yield from objects(value)


def test_schema_entity_types_are_exactly_the_ontology(ontology):
    schema = response_schema(ontology)
    entity = schema["properties"]["entities"]["items"]
    assert entity["properties"]["type"]["enum"] == list(ontology.entity_names)


def test_schema_relations_cover_exactly_the_allowed_triples(ontology):
    offered = set()
    for branch in response_schema(ontology)["properties"]["relations"]["items"]["anyOf"]:
        p = branch["properties"]
        for relation in p["relation"]["enum"]:
            for source in p["source_type"]["enum"]:
                for target in p["target_type"]["enum"]:
                    offered.add((source, relation, target))

    expected = {(s, r, t) for r, pairs in ontology.allowed_pairs.items() for s, t in pairs}
    assert offered == expected


def test_schema_meets_strict_structured_output_rules(ontology):
    for node in objects(response_schema(ontology)):
        assert node["additionalProperties"] is False
        assert sorted(node["required"]) == sorted(node["properties"])


def test_prompt_describes_the_ontology_and_the_sentence(ontology):
    prompt = build_prompt(
        "APT28 used X-Agent .", ontology, known=[[0, 1, "APT28", "ThreatGroup"]], examples=[]
    )
    for name in ontology.entity_names:
        assert f"- {name}: " in prompt
    assert "- uses: ThreatActor -> Malware" in prompt
    assert "- sub_technique_of: " in prompt
    assert '- "APT28" (ThreatGroup)' in prompt
    assert prompt.rstrip().endswith("APT28 used X-Agent .")


def test_shipped_examples_only_teach_allowed_relations(ontology):
    examples = load_examples()
    assert examples
    for example in examples:
        types = {e["text"]: e["type"] for e in example["entities"]}
        for r in example["relations"]:
            pair = (types[r["source"]], types[r["target"]])
            assert pair in ontology.allowed_pairs[r["relation"]], r
    prompt = build_prompt("x", ontology)
    assert '"source_type": "ThreatGroup"' in prompt


def test_parse_keeps_valid_entities_and_relations(ontology):
    raw = reply(
        [("APT28", "ThreatGroup"), ("X-Agent", "Malware")],
        [("APT28", "ThreatGroup", "uses", "X-Agent", "Malware")],
    )
    assert parse_response(raw, ontology) == (
        [("APT28", "ThreatGroup"), ("X-Agent", "Malware")],
        [("APT28", "uses", "X-Agent")],
    )


def test_parse_drops_relation_whose_end_is_not_an_entity(ontology):
    raw = reply([("APT28", "ThreatGroup")], [("APT28", "ThreatGroup", "uses", "PlugX", "Malware")])
    assert parse_response(raw, ontology)[1] == []


def test_parse_drops_relation_with_wrong_claimed_type(ontology):
    raw = reply(
        [("APT28", "ThreatGroup"), ("X-Agent", "Malware")],
        [("APT28", "ThreatGroup", "uses", "X-Agent", "Tool")],
    )
    assert parse_response(raw, ontology)[1] == []


def test_parse_drops_triples_the_ontology_forbids(ontology):
    raw = reply(
        [("X-Agent", "Malware"), ("banks", "Organization")],
        [("X-Agent", "Malware", "targets", "banks", "Organization")],
    )
    assert parse_response(raw, ontology)[1] == []


def test_parse_drops_unknown_types_and_blank_text(ontology):
    raw = reply([("thing", "Gadget"), ("  ", "Malware"), ("PlugX", "Malware")])
    assert parse_response(raw, ontology)[0] == [("PlugX", "Malware")]


def test_parse_lets_relations_use_already_found_spans(ontology):
    raw = reply([("X-Agent", "Malware")], [("APT28", "ThreatGroup", "uses", "X-Agent", "Malware")])
    known = [[0, 1, "APT28", "ThreatGroup"]]
    assert parse_response(raw, ontology, known)[1] == [("APT28", "uses", "X-Agent")]


@pytest.mark.parametrize(
    "raw", ["not json", "[]", '{"entities": []}', '{"entities": [1], "relations": []}']
)
def test_parse_rejects_malformed_replies(ontology, raw):
    with pytest.raises(ValueError, match="unusable reply"):
        parse_response(raw, ontology)


class ScriptedComplete:
    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, dict]] = []
        self.last_model = "model-a"

    async def __call__(self, prompt: str, schema: dict) -> str:
        self.calls.append((prompt, schema))
        return self.replies.pop(0)


async def test_extractor_sends_the_prompt_and_the_strict_schema(ontology):
    complete = ScriptedComplete(reply([("PlugX", "Malware")]))
    extractor = LLMExtractor(complete, ontology, examples=[])

    assert await extractor.extract("it used PlugX .") == ([("PlugX", "Malware")], [])
    prompt, schema = complete.calls[0]
    assert "it used PlugX ." in prompt
    assert schema == response_schema(ontology)
    assert extractor.model_name == "model-a"


async def test_extractor_retries_once_on_an_unusable_reply(ontology):
    complete = ScriptedComplete("garbage", reply([("PlugX", "Malware")]))
    extractor = LLMExtractor(complete, ontology, examples=[])

    assert await extractor.extract("it used PlugX .") == ([("PlugX", "Malware")], [])
    assert len(complete.calls) == 2


async def test_extractor_raises_after_repeated_unusable_replies(ontology):
    extractor = LLMExtractor(ScriptedComplete("garbage", "worse"), ontology, examples=[])
    with pytest.raises(ValueError, match="no usable reply after 2 attempts"):
        await extractor.extract("it used PlugX .")

import pytest

from crawler.extraction.pipeline import DocumentExtraction, RelationTriple, extract_text
from crawler.extraction.rules import RuleMatcher

MATCHER = RuleMatcher(
    [
        {"name": "APT28", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
        {"name": "Fancy Bear", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
        {"name": "X-Agent", "type": "Malware", "id": "S0161", "case_sensitive": True},
        {"name": "Germany", "type": "Location", "id": "DE", "case_sensitive": True},
    ]
)


class FakeLLM:
    def __init__(self, answers=None, fail_on: str | None = None) -> None:
        self.answers = answers or {}
        self.fail_on = fail_on
        self.calls: list[tuple[str, list[str]]] = []

    async def extract(self, sentence, known=()):
        self.calls.append((sentence, [k[2] for k in known]))
        if self.fail_on and self.fail_on in sentence:
            raise RuntimeError("quota exceeded")
        for needle, answer in self.answers.items():
            if needle in sentence:
                return answer
        return [], []


def named(result, relation: RelationTriple) -> tuple[str, str, str]:
    return (
        result.entities[relation.source].text,
        relation.relation,
        result.entities[relation.target].text,
    )


async def test_rules_only_entities_carry_exact_character_offsets(ontology):
    text = "APT28, also known as Fancy Bear, used X-Agent.\n\nIt was seen in Germany in March 2019."

    result = await extract_text(text, MATCHER, ontology)

    assert [(e.text, e.type, e.sentence, e.origin) for e in result.entities] == [
        ("APT28", "ThreatGroup", 0, "rules"),
        ("Fancy Bear", "ThreatGroup", 0, "rules"),
        ("X-Agent", "Malware", 0, "rules"),
        ("Germany", "Location", 1, "rules"),
        ("March 2019", "Time", 1, "rules"),
    ]
    assert all(text[e.start : e.end] == e.text for e in result.entities)
    assert result.relations == (RelationTriple(0, "alias-of", 1, 0),)
    assert (result.sentences, result.llm_failures) == (2, 0)


async def test_llm_entities_and_relations_are_merged(ontology):
    text = "APT28 used X-Agent against NATO."
    llm = FakeLLM(
        {
            "NATO": (
                [("NATO", "Organization")],
                [("APT28", "targets", "NATO"), ("APT28", "uses", "X-Agent")],
            )
        }
    )

    result = await extract_text(text, MATCHER, ontology, llm)

    nato = next(e for e in result.entities if e.text == "NATO")
    assert (nato.type, nato.origin, text[nato.start : nato.end]) == ("Organization", "llm", "NATO")
    assert {named(result, r) for r in result.relations} == {
        ("APT28", "targets", "NATO"),
        ("APT28", "uses", "X-Agent"),
    }
    assert llm.calls == [("APT28 used X-Agent against NATO .", ["APT28", "X-Agent"])]


async def test_llm_cannot_relabel_a_rule_span(ontology):
    llm = FakeLLM({"X-Agent": ([("X-Agent", "Tool")], [])})
    result = await extract_text("APT28 used X-Agent.", MATCHER, ontology, llm)
    assert [(e.text, e.type) for e in result.entities] == [
        ("APT28", "ThreatGroup"),
        ("X-Agent", "Malware"),
    ]


async def test_relations_the_ontology_forbids_are_dropped_and_recorded(ontology):
    llm = FakeLLM({"NATO": ([("NATO", "Organization")], [("X-Agent", "targets", "NATO")])})

    result = await extract_text("APT28 used X-Agent against NATO.", MATCHER, ontology, llm)

    assert result.relations == ()
    assert any("does not allow Malware targets Organization" in d for d in result.dropped)


async def test_llm_failure_keeps_rules_and_is_reported(ontology):
    llm = FakeLLM(fail_on="Germany")

    result = await extract_text("APT28 used X-Agent. They hit Germany.", MATCHER, ontology, llm)

    assert result.llm_failures == 1
    assert result.warnings == ("sentence 1: LLM failed (RuntimeError: quota exceeded); rules only",)
    assert "Germany" in {e.text for e in result.entities}


@pytest.mark.parametrize(
    "text",
    [
        "The “Sofacy” group’s  loader,\tX-Agent, hit Germany.",
        "  APT28's   implant (X-Agent) contacted evil[.]com!  ",
        "Line one about APT28.\r\nLine two: X-Agent in Germany?",
        "APT28 — also Fancy Bear — used X-Agent… again in 2019.",
    ],
)
async def test_offsets_survive_quotes_possessives_and_whitespace(ontology, text):
    result = await extract_text(text, MATCHER, ontology)

    assert result.entities
    for e in result.entities:
        assert text[e.start : e.end] == e.text


async def test_relation_ids_are_global_across_sentences(ontology):
    llm = FakeLLM({"Germany": ([], [("APT28", "operates-in", "Germany")])})

    result = await extract_text("X-Agent spread. APT28 hit Germany.", MATCHER, ontology, llm)

    [relation] = result.relations
    assert named(result, relation) == ("APT28", "operates-in", "Germany")
    assert relation.sentence == 1
    assert [e.id for e in result.entities] == [0, 1, 2]


async def test_empty_text_yields_nothing(ontology):
    assert await extract_text("   \n ", MATCHER, ontology, FakeLLM()) == DocumentExtraction(
        (), (), 0, 0
    )

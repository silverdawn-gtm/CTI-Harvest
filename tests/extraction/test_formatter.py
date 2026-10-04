import pytest

from crawler.extraction.formatter import locate_spans, resolve_triples, token_offsets
from crawler.extraction.tokenizer import tokenize

TEXT = "The admin@338 has largely targeted organizations with PlugX ."


def test_locate_spans_finds_token_positions():
    spans = locate_spans(TEXT, [("admin@338", "ThreatGroup"), ("organizations", "Organization")])
    assert spans == [[1, 2, "admin@338", "ThreatGroup"], [5, 6, "organizations", "Organization"]]


def test_locate_spans_handles_multi_token_entities():
    spans = locate_spans("the Fancy Bear group", [("Fancy Bear", "ThreatGroup")])
    assert spans == [[1, 3, "Fancy Bear", "ThreatGroup"]]


def test_locate_spans_takes_next_unused_occurrence_for_repeats():
    spans = locate_spans("PlugX drops PlugX", [("PlugX", "Malware"), ("PlugX", "Malware")])
    assert spans == [[0, 1, "PlugX", "Malware"], [2, 3, "PlugX", "Malware"]]


def test_locate_spans_drops_entities_not_in_text():
    assert locate_spans(TEXT, [("Lazarus", "ThreatGroup")]) == []


def test_locate_spans_drops_overlaps_and_respects_taken():
    spans = locate_spans(
        "the Fancy Bear group",
        [("Fancy Bear", "ThreatGroup"), ("Bear", "ThreatGroup")],
    )
    assert spans == [[1, 3, "Fancy Bear", "ThreatGroup"]]
    assert locate_spans("uses PlugX", [("PlugX", "Tool")], taken=[[1, 2, "PlugX", "Malware"]]) == []


def test_locate_spans_tolerates_spacing_and_a_sentence_period():
    assert locate_spans("uses the  Fancy   Bear tool", [("Fancy Bear", "ThreatGroup")]) == [
        [2, 4, "Fancy Bear", "ThreatGroup"]
    ]
    assert locate_spans("it uses PlugX .", [("PlugX.", "Malware")]) == [[2, 3, "PlugX", "Malware"]]


def test_resolve_triples_maps_surfaces_to_span_indices():
    spans = [[0, 1, "APT28", "ThreatGroup"], [2, 3, "PlugX", "Malware"]]
    assert resolve_triples(spans, [("APT28", "uses", "PlugX"), ("APT28", "uses", "Nope")]) == [
        (0, "uses", 1)
    ]


@pytest.mark.parametrize(
    "sentence",
    [
        "APT28 used X-Agent.",
        "The “Sofacy” group’s  loader,\tX-Agent, hit (Germany)!",
        "  APT28's   implant contacted evil[.]com?  ",
        "Line one about APT28 and\r\nX-Agent: done.",
    ],
)
def test_token_offsets_slice_the_original_sentence(sentence):
    tokens = tokenize(sentence).split()
    offsets = token_offsets(sentence, tokens)

    assert [sentence[s:e] for s, e in offsets] == tokens
    assert all(a[1] <= b[0] for a, b in zip(offsets, offsets[1:], strict=False))


def test_token_offsets_rejects_tokens_not_in_the_sentence():
    with pytest.raises(ValueError, match="not found"):
        token_offsets("APT28 used X-Agent", ["APT28", "PlugX"])

from crawler.extraction.validator import validate

SPANS = [
    [0, 1, "APT28", "ThreatGroup"],
    [2, 3, "X-Agent", "Malware"],
    [5, 6, "banks", "Organization"],
    [7, 8, "Germany", "Location"],
]


def test_keeps_allowed_triples(ontology):
    spans, triples, dropped = validate(
        SPANS, [(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)], ontology
    )
    assert spans == SPANS
    assert triples == [(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)]
    assert dropped == []


def test_drops_triples_the_ontology_does_not_allow(ontology):
    _, triples, dropped = validate(SPANS, [(1, "targets", 2)], ontology)
    assert triples == []
    assert dropped == [
        "X-Agent targets banks: ontology does not allow Malware targets Organization"
    ]


def test_drops_unknown_relation_names(ontology):
    _, triples, dropped = validate(SPANS, [(0, "loves", 1)], ontology)
    assert triples == [] and dropped == ["loves: unknown relation"]


def test_turns_inverse_names_into_the_stored_direction(ontology):
    _, triples, _ = validate(SPANS, [(1, "used-by", 0)], ontology)
    assert triples == [(0, "uses", 1)]


def test_generic_relation_only_when_nothing_specific_fits(ontology):
    _, kept, dropped = validate(SPANS, [(0, "located-in", 3), (1, "located-in", 3)], ontology)
    assert kept == [(1, "located-in", 3)]
    assert "ThreatGroup located-in Location" in dropped[0]


def test_drops_unknown_entity_types_and_reindexes(ontology):
    spans = [[9, 10, "thing", "Gadget"], *SPANS]
    kept, triples, dropped = validate(spans, [(0, "uses", 2), (1, "operates-in", 4)], ontology)

    assert [s[2] for s in kept] == ["APT28", "X-Agent", "banks", "Germany"]
    assert triples == [(0, "operates-in", 3)]
    assert "thing: unknown entity type Gadget" in dropped


def test_drops_self_loops_and_duplicates(ontology):
    _, triples, _ = validate(SPANS, [(0, "uses", 0), (0, "uses", 1), (1, "used-by", 0)], ontology)
    assert triples == [(0, "uses", 1)]


def test_alias_between_groups_is_allowed_in_either_order(ontology):
    spans = [[0, 1, "APT28", "ThreatGroup"], [4, 6, "Fancy Bear", "ThreatGroup"]]
    _, triples, _ = validate(spans, [(1, "alias-of", 0)], ontology)
    assert triples == [(1, "alias-of", 0)]

from validator import validate

ALL = {"ThreatGroup", "Malware", "Organization", "Location", "Time", "Vulnerability"}
SPANS = [[0, 1, "APT28", "ThreatGroup"], [2, 3, "X-Agent", "Malware"],
         [5, 6, "banks", "Organization"], [7, 8, "Germany", "Location"]]


def run(triples, spans=SPANS, types=ALL, relations=None):
    return validate(spans, triples, types, relations)


def test_keeps_allowed_triples():
    spans, triples, dropped = run([(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)])
    assert spans == SPANS
    assert triples == [(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)]
    assert dropped == []


def test_drops_triples_the_schema_does_not_allow():
    _, triples, dropped = run([(1, "targets", 2)])
    assert triples == []
    assert "Malware targets Organization" in dropped[0]["reason"]


def test_drops_unknown_relation_names():
    _, triples, dropped = run([(0, "loves", 1)])
    assert triples == [] and "unknown relation" in dropped[0]["reason"]


def test_turns_inverse_names_into_the_stored_direction():
    _, triples, _ = run([(1, "used-by", 0)])
    assert triples == [(0, "uses", 1)]


def test_drops_generic_relation_when_a_specific_one_fits():
    _, triples, dropped = run([(0, "located-in", 3)])
    assert triples == [] and "specific relation" in dropped[0]["reason"]


def test_keeps_generic_relation_when_nothing_specific_fits():
    _, triples, _ = run([(1, "located-in", 3)])
    assert triples == [(1, "located-in", 3)]


def test_drops_unselected_relations():
    _, triples, dropped = run([(0, "uses", 1), (0, "targets", 2)], relations={"targets"})
    assert triples == [(0, "targets", 2)] and "not selected" in dropped[0]["reason"]


def test_drops_unselected_and_unknown_entity_types_and_reindexes():
    spans = SPANS + [[9, 10, "thing", "Gadget"]]
    kept, triples, dropped = run([(0, "targets", 2), (0, "operates-in", 3)], spans=spans,
                                 types={"ThreatGroup", "Location"})
    assert [s[2] for s in kept] == ["APT28", "Germany"]
    assert triples == [(0, "operates-in", 1)]
    assert {d["item"] for d in dropped} >= {"X-Agent", "banks", "thing"}


def test_drops_self_loops_and_duplicates():
    _, triples, _ = run([(0, "uses", 0), (0, "uses", 1), (1, "used-by", 0)])
    assert triples == [(0, "uses", 1)]


def test_alias_between_groups_is_allowed_in_either_order():
    spans = [[0, 1, "APT28", "ThreatGroup"], [4, 6, "Fancy Bear", "ThreatGroup"]]
    _, triples, _ = run([(1, "alias-of", 0)], spans=spans)
    assert triples == [(1, "alias-of", 0)]


def test_custom_relation_survives_validation(isolated_custom_schema):
    import json
    from ontology import reload_schema
    isolated_custom_schema.write_text(json.dumps({
        "entity_types": [{"name": "CryptoWallet", "label": "Crypto wallet", "description": "A wallet."}],
        "relations": [{"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
                       "pairs": [["ThreatGroup", "CryptoWallet"]]}]}), encoding="utf-8")
    reload_schema()
    spans = [[0, 1, "Lazarus", "ThreatGroup"], [4, 5, "4AdUndX", "CryptoWallet"]]
    kept, triples, dropped = validate(spans, [(1, "paid-by", 0)], {"ThreatGroup", "CryptoWallet"})
    assert triples == [(0, "pays-to", 1)] and dropped == []

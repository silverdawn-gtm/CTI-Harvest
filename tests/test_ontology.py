"""schema/schema.json must encode Entities_and_relations_1.pdf exactly, plus documented assumptions."""
import pytest

from ontology import load_base_schema, load_schema, reload_schema

# Every "source -> relation -> target" line of the PDF, by entity ID.
PDF_TRIPLES = [
    (1, "alias-of", 2), (2, "alias-of", 1),
    (1, "uses", 3), (1, "uses", 4), (1, "uses", 7), (1, "uses", 9), (1, "uses", 6),
    (2, "uses", 3), (2, "uses", 4), (2, "uses", 7), (2, "uses", 9),
    (1, "targets", 8), (1, "targets", 12), (2, "targets", 8), (2, "targets", 12),
    (1, "operates-in", 15), (2, "operates-in", 15),
    (1, "active-at", 14), (2, "active-at", 14),
    (1, "originated-from", 15), (2, "originated-from", 15),
    (3, "variant-of", 3), (7, "variant-of", 7),
    (3, "drops", 10), (3, "exploits", 5), (3, "affects", 6), (3, "affects", 12), (7, "exploits", 5),
    (3, "communicates-with", 11), (7, "communicates-with", 11),
    (6, "contains", 5), (6, "runs-on", 12),
    (4, "sub-technique-of", 4), (9, "variant-of", 9),
    (4, "uses", 7), (4, "uses", 3), (9, "uses", 7),
    (4, "targets", 5), (4, "targets", 12),
    (4, "mitigated-by", 13),
    (5, "affects", 6), (5, "affects", 12), (5, "remediated-by", 6),
    (12, "belongs-to", 8), (12, "located-in", 15), (12, "monitored-by", 13),
    (10, "indicates", 3), (10, "indicates", 1), (10, "downloads-from", 11),
    (11, "belongs-to", 8), (11, "located-in", 15),
    (11, "utilized-by", 1), (11, "utilized-by", 2), (11, "utilized-by", 3),
    (13, "investigates", 1), (13, "investigates", 2),
    (13, "detects", 3), (13, "detects", 5), (13, "detects", 9),
    (13, "mitigates", 5), (13, "patches", 12),
]
ASSUMED_TRIPLES = [(2, "uses", 6), (2, "alias-of", 2)]


@pytest.fixture(scope="module")
def schema():
    return load_base_schema()


def test_has_the_15_pdf_entity_types(schema):
    assert [t.id for t in schema.entity_types] == list(range(1, 16))
    assert schema.type_name(1) == "ThreatActor" and schema.type_name(15) == "Location"


@pytest.mark.parametrize("src,rel,tgt", PDF_TRIPLES)
def test_every_pdf_relation_is_allowed(schema, src, rel, tgt):
    assert schema.allowed(schema.type_name(src), rel, schema.type_name(tgt))


@pytest.mark.parametrize("src,rel,tgt", ASSUMED_TRIPLES)
def test_assumed_relations_are_allowed(schema, src, rel, tgt):
    assert schema.allowed(schema.type_name(src), rel, schema.type_name(tgt))


def test_only_pdf_and_assumed_pairs_are_encoded(schema):
    expected = set(PDF_TRIPLES) | set(ASSUMED_TRIPLES)
    # the PDF's "4 mitigated-by 13" is stored as "13 mitigates 4"
    expected = {(13, "mitigates", 4) if t == (4, "mitigated-by", 13) else t for t in expected}
    assert schema.specific_triples() == expected


def test_assumptions_are_documented(schema):
    assert {tuple(a["triple"]) for a in schema.assumptions} == set(ASSUMED_TRIPLES)


def test_any_entity_can_link_to_time_and_location(schema):
    assert schema.allowed("Malware", "occurs-at", "Time")
    assert schema.allowed("Vulnerability", "located-in", "Location")
    assert not schema.allowed("Malware", "occurs-at", "Location")


def test_generic_relations_are_flagged(schema):
    assert schema.is_generic("occurs-at", "Malware", "Time")
    assert schema.is_generic("located-in", "Malware", "Location")
    assert not schema.is_generic("located-in", "Asset", "Location")


def test_inverse_names_are_allowed_in_reverse(schema):
    assert schema.allowed("Malware", "used-by", "ThreatGroup")
    assert schema.allowed("Vulnerability", "mitigated-by", "SecurityTeam")
    assert schema.allowed("AttackTechnique", "mitigated-by", "SecurityTeam")
    assert not schema.allowed("ThreatGroup", "used-by", "Malware")


def test_disallowed_triples_are_rejected(schema):
    assert not schema.allowed("Malware", "targets", "Organization")
    assert not schema.allowed("ThreatGroup", "nonsense", "Malware")
    assert not schema.allowed("Nope", "uses", "Malware")


def test_inverse_lookup_both_ways(schema):
    assert schema.inverse("uses") == "used-by"
    assert schema.inverse("used-by") == "uses"
    assert schema.inverse("alias-of") == "alias-of"


def test_relation_names_are_unique(schema):
    names = [n for r in schema.relations for n in {r.name, r.inverse}]
    assert len(names) == len(set(names))


def test_canonical_orients_to_the_stored_direction(schema):
    assert schema.canonical("ThreatGroup", "uses", "Malware") == ("uses", False)
    assert schema.canonical("Malware", "used-by", "ThreatGroup") == ("uses", True)


def test_every_type_has_a_group_and_description(schema):
    assert all(t.group and t.description for t in schema.entity_types)


def test_presets_use_known_types(schema):
    names = {t.name for t in schema.entity_types}
    assert set(schema.presets["IOCs only"]) == {"FileHash", "NetworkInfra", "Vulnerability"}
    assert all(set(v) <= names for v in schema.presets.values())


# --- relations available for a selection -------------------------------------------------

def test_relations_for_keeps_only_pairs_with_both_types_selected(schema):
    rels = schema.relations_for({"ThreatGroup", "Malware"})
    assert rels == {"alias-of": [("ThreatGroup", "ThreatGroup")], "uses": [("ThreatGroup", "Malware")],
                    "variant-of": [("Malware", "Malware")]}


def test_relations_for_expands_generic_relations_to_selected_sources(schema):
    rels = schema.relations_for({"Malware", "Time"})
    assert rels["occurs-at"] == [("Malware", "Time")]


def test_relations_for_skips_generic_pair_when_a_specific_relation_fits(schema):
    rels = schema.relations_for({"ThreatGroup", "Time", "Malware"})
    assert rels["active-at"] == [("ThreatGroup", "Time")]
    assert rels["occurs-at"] == [("Malware", "Time")]


def test_relations_for_respects_relation_selection(schema):
    rels = schema.relations_for({"ThreatGroup", "Malware", "Location"}, relation_types={"operates-in"})
    assert set(rels) == {"operates-in"}


def test_relations_for_accepts_inverse_names_in_selection(schema):
    rels = schema.relations_for({"ThreatGroup", "Malware"}, relation_types={"used-by"})
    assert set(rels) == {"uses"}


def test_relations_for_includes_self_pairs(schema):
    assert schema.relations_for({"Malware"}) == {"variant-of": [("Malware", "Malware")]}


# --- custom overlay (schema/custom.json) -------------------------------------------------
import json

CUSTOM = {
    "entity_types": [{"name": "CryptoWallet", "label": "Crypto wallet",
                      "description": "A cryptocurrency wallet or address."}],
    "relations": [{"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
                   "pairs": [["ThreatGroup", "CryptoWallet"]]}],
}


def write_custom(path, data):
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    reload_schema()


def test_tests_use_a_temporary_custom_file(isolated_custom_schema):
    import ontology
    assert ontology.CUSTOM_PATH == isolated_custom_schema
    assert isolated_custom_schema != ontology.SCHEMA_DIR / "custom.json"


def test_without_a_custom_file_the_schema_is_the_base():
    assert [t.name for t in load_schema().entity_types] == [t.name for t in load_base_schema().entity_types]


def test_custom_entity_type_is_merged_into_a_custom_group(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    t = load_schema().entity_types[-1]
    assert (t.id, t.name, t.label, t.group) == (101, "CryptoWallet", "Crypto wallet", "Custom")
    assert load_schema().is_custom("CryptoWallet") and load_schema().is_custom("pays-to")
    assert not load_schema().is_custom("Malware")


def test_custom_relation_works_like_a_built_in_one(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    s = load_schema()
    assert s.allowed("ThreatGroup", "pays-to", "CryptoWallet")
    assert s.allowed("CryptoWallet", "paid-by", "ThreatGroup")
    assert not s.allowed("Malware", "pays-to", "CryptoWallet")
    assert s.inverse("pays-to") == "paid-by"
    assert s.relations_for({"ThreatGroup", "CryptoWallet"})["pays-to"] == [("ThreatGroup", "CryptoWallet")]


def test_everything_preset_includes_custom_types(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    assert load_schema().presets["Everything"][-1] == "CryptoWallet"
    assert len(load_schema().presets["Everything"]) == 16


def test_custom_items_never_reach_the_base_schema(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    assert "CryptoWallet" not in {t.name for t in load_base_schema().entity_types}


def test_custom_pairs_with_unknown_types_are_skipped(isolated_custom_schema):
    data = {"entity_types": [], "relations": [
        {"name": "haunts", "inverse": "haunted-by", "description": "ghost story",
         "pairs": [["ThreatGroup", "Ghost"]]}]}
    write_custom(isolated_custom_schema, data)
    assert "haunts" not in {r.name for r in load_schema().relations}


def test_invalid_custom_json_gives_a_clear_error(isolated_custom_schema):
    from ontology import CustomFileError
    write_custom(isolated_custom_schema, "{oops")
    with pytest.raises(CustomFileError, match="custom.json is not valid JSON"):
        load_schema()


# --- final review fix 2: hand-edited custom.json ------------------------------------------

def test_custom_file_saved_with_a_byte_order_mark_loads(isolated_custom_schema):
    isolated_custom_schema.write_bytes(b"\xef\xbb\xbf" + json.dumps(CUSTOM).encode("utf-8"))
    reload_schema()
    assert load_schema().is_custom("CryptoWallet")


def test_custom_file_in_utf16_gives_a_clear_error(isolated_custom_schema):
    from ontology import CustomFileError
    isolated_custom_schema.write_text(json.dumps(CUSTOM), encoding="utf-16")
    reload_schema()
    with pytest.raises(CustomFileError, match="UTF-8"):
        load_schema()


@pytest.mark.parametrize("content,where", [
    ("[]", "must be a JSON object"),
    ('{"entity_types": null}', "entity_types must be a list"),
    ('{"entity_types": [{"name": "X1"}]}', "entity_types[0]"),
    ('{"entity_types": [{"name": "bad name", "label": "x", "description": "a thing"}]}', "entity_types[0]"),
    ('{"relations": [{"name": "r-x", "inverse": "r-y", "description": "d", "pairs": [["A"]]}]}', "relations[0]"),
    ('{"entity_types": [{"name": "Malware", "label": "x", "description": "a thing"}]}', "Malware"),
    ('{"relations": [{"name": "uses", "inverse": "x-y", "description": "d", "pairs": []}]}', "uses"),
])
def test_badly_shaped_custom_file_names_the_problem(isolated_custom_schema, content, where):
    from ontology import CustomFileError
    write_custom(isolated_custom_schema, content)
    with pytest.raises(CustomFileError) as err:
        load_schema()
    assert where in str(err.value) and "custom.json" in str(err.value)

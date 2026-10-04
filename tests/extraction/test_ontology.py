import json

import pytest

from crawler.extraction.ontology import OntologyError, load_ontology, parse_ontology

SPEC_LABELS = [
    "Threat actor", "Threat group", "Malware", "Attack technique", "Vulnerability", "Software",
    "Tool", "Organization", "Attack pattern", "File/hash", "Network infrastructure",
    "Asset/system", "Security team", "Time", "Location",
]  # fmt: skip

ACTORS = ("ThreatActor", "ThreatGroup")
MAL_TOOL = ("Malware", "Tool")
TECH = ("AttackTechnique", "AttackPattern")

# CTI_INTEGRATION.md, Objective 2, every line spelled out. "A/B" means every combination.
SPEC_TRIPLES = [
    *[(a, "alias-of", b) for a in ACTORS for b in ACTORS],
    *[
        (a, "uses", t)
        for a in ACTORS
        for t in ("Malware", "AttackTechnique", "Tool", "AttackPattern", "Software")
    ],
    *[(a, "targets", t) for a in ACTORS for t in ("Organization", "Asset")],
    *[(a, r, "Location") for a in ACTORS for r in ("operates-in", "originated-from")],
    *[(a, "active-at", "Time") for a in ACTORS],
    *[(a, "variant-of", b) for a in MAL_TOOL for b in MAL_TOOL],
    ("Malware", "drops", "FileHash"),
    *[(a, "exploits", "Vulnerability") for a in MAL_TOOL],
    *[("Malware", "affects", t) for t in ("Software", "Asset")],
    *[(a, "communicates-with", "NetworkInfra") for a in MAL_TOOL],
    ("Software", "contains", "Vulnerability"),
    ("Software", "runs-on", "Asset"),
    *[(a, r, b) for a in TECH for b in TECH for r in ("sub_technique_of", "variant-of")],
    *[("AttackTechnique", "uses", t) for t in ("Tool", "Malware")],
    *[("AttackTechnique", "targets", t) for t in ("Vulnerability", "Asset")],
    ("AttackTechnique", "mitigated-by", "SecurityTeam"),
    *[("Vulnerability", "affects", t) for t in ("Software", "Asset")],
    ("Vulnerability", "remediated-by", "Software"),
    ("Asset", "belongs-to", "Organization"),
    ("Asset", "located-in", "Location"),
    ("Asset", "monitored-by", "SecurityTeam"),
    *[("FileHash", "indicates", t) for t in ("Malware", "ThreatActor")],
    ("FileHash", "downloads-from", "NetworkInfra"),
    ("NetworkInfra", "belongs-to", "Organization"),
    ("NetworkInfra", "located-in", "Location"),
    *[("NetworkInfra", "utilized-by", t) for t in (*ACTORS, "Malware")],
    *[("SecurityTeam", "investigates", t) for t in ACTORS],
    *[("SecurityTeam", "detects", t) for t in ("Malware", "Vulnerability", "AttackPattern")],
    ("SecurityTeam", "mitigates", "Vulnerability"),
    ("SecurityTeam", "patches", "Asset"),
]


def test_shipped_ontology_has_exactly_the_fifteen_spec_types(ontology):
    assert [t.label for t in ontology.entity_types] == SPEC_LABELS
    assert len(set(ontology.entity_names)) == 15


@pytest.mark.parametrize("triple", SPEC_TRIPLES, ids=lambda t: " ".join(t))
def test_every_spec_triple_is_allowed(ontology, triple):
    assert ontology.allowed(*triple)


def test_specific_pairs_are_exactly_the_spec_table(ontology):
    def stored(source, relation, target):
        name, flipped = ontology.canonical(relation)
        return (target, name, source) if flipped else (source, name, target)

    in_file = {(s, r.name, t) for r in ontology.relations for s, t in r.pairs}
    assert in_file == {stored(*t) for t in SPEC_TRIPLES}


@pytest.mark.parametrize(
    "triple",
    [
        ("Malware", "occurs-at", "Time"),
        ("Vulnerability", "occurs-at", "Time"),
        ("Organization", "located-in", "Location"),
        ("SecurityTeam", "located-in", "Location"),
    ],
)
def test_any_entity_relations_reach_time_and_location(ontology, triple):
    assert ontology.allowed(*triple)


@pytest.mark.parametrize(
    "triple",
    [
        ("ThreatGroup", "located-in", "Location"),  # operates-in / originated-from fit
        ("ThreatActor", "occurs-at", "Time"),  # active-at fits
        ("Time", "occurs-at", "Time"),
        ("Location", "located-in", "Location"),
    ],
)
def test_generic_relations_yield_to_specific_ones(ontology, triple):
    assert not ontology.allowed(*triple)


@pytest.mark.parametrize(
    "triple",
    [
        ("Malware", "targets", "Organization"),
        ("Tool", "drops", "FileHash"),
        ("AttackPattern", "uses", "Tool"),
        ("Software", "exploits", "Vulnerability"),
        ("Organization", "uses", "Malware"),
        ("Malware", "loves", "Tool"),
        ("Gadget", "uses", "Malware"),
    ],
)
def test_triples_outside_the_spec_are_refused(ontology, triple):
    assert not ontology.allowed(*triple)


def test_inverse_names_are_checked_in_the_stored_direction(ontology):
    assert ontology.canonical("used-by") == ("uses", True)
    assert ontology.canonical("uses") == ("uses", False)
    assert ontology.canonical("loves") == (None, False)
    assert ontology.allowed("Malware", "used-by", "ThreatGroup")
    assert not ontology.allowed("ThreatGroup", "used-by", "Malware")


def minimal(**relation) -> dict:
    return {
        "version": "t",
        "entity_types": [
            {"name": "Malware", "label": "Malware", "description": "m"},
            {"name": "Tool", "label": "Tool", "description": "t"},
        ],
        "relations": [
            {
                "name": "uses",
                "inverse": "used-by",
                "description": "d",
                "pairs": [["Malware", "Tool"]],
                **relation,
            }
        ],
    }


@pytest.mark.parametrize(
    "data, message",
    [
        (minimal(pairs=[["Malware", "Gadget"]]), "unknown entity type Gadget"),
        (minimal(pairs=[], generic_target="Gadget"), "unknown entity type Gadget"),
        (minimal(pairs=[]), "allows no pairs"),
        (minimal(inverse="uses"), None),  # self-inverse is legal (alias-of)
        (minimal(extra="x"), "extra"),
        ({**minimal(), "version": ""}, "version"),
    ],
)
def test_parse_ontology_checks_consistency(data, message):
    if message is None:
        parse_ontology(data)
        return
    with pytest.raises(OntologyError, match=message):
        parse_ontology(data)


def test_duplicate_entity_types_are_refused():
    data = minimal()
    data["entity_types"].append({"name": "Tool", "label": "again", "description": "d"})
    with pytest.raises(OntologyError, match="duplicate entity type Tool"):
        parse_ontology(data)


def test_relation_names_must_not_collide():
    data = minimal()
    data["relations"].append(
        {"name": "drops", "inverse": "used-by", "description": "d", "pairs": [["Malware", "Tool"]]}
    )
    with pytest.raises(OntologyError, match="used-by"):
        parse_ontology(data)


def test_load_ontology_reports_bad_files(tmp_path):
    with pytest.raises(OntologyError, match="not found"):
        load_ontology(tmp_path / "missing.json")

    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(OntologyError, match="not valid JSON"):
        load_ontology(bad)

    good = tmp_path / "good.json"
    good.write_text(json.dumps(minimal()), encoding="utf-8")
    assert load_ontology(good).entity_names == ("Malware", "Tool")

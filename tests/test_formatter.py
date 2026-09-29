import dnrti
from formatter import (bio_tags, build_record, build_relations, format_record, locate_spans,
                       record_from_tokens, select)

TEXT = "The admin@338 has largely targeted organizations with PlugX ."


def test_locate_spans_finds_token_positions():
    spans = locate_spans(TEXT, [("admin@338", "HackOrg"), ("organizations", "Org")])
    assert spans == [[1, 2, "admin@338", "HackOrg"], [5, 6, "organizations", "Org"]]


def test_locate_spans_handles_multi_token_entities():
    spans = locate_spans("the Fancy Bear group", [("Fancy Bear", "HackOrg")])
    assert spans == [[1, 3, "Fancy Bear", "HackOrg"]]


def test_locate_spans_takes_next_unused_occurrence_for_repeats():
    spans = locate_spans("PlugX drops PlugX", [("PlugX", "Tool"), ("PlugX", "Tool")])
    assert spans == [[0, 1, "PlugX", "Tool"], [2, 3, "PlugX", "Tool"]]


def test_locate_spans_drops_entities_not_in_text():
    assert locate_spans(TEXT, [("Lazarus", "HackOrg")]) == []


def test_locate_spans_drops_entities_overlapping_an_earlier_one():
    spans = locate_spans("the Fancy Bear group", [("Fancy Bear", "HackOrg"), ("Bear", "HackOrg")])
    assert spans == [[1, 3, "Fancy Bear", "HackOrg"]]


def test_locate_spans_sorts_by_position():
    spans = locate_spans(TEXT, [("organizations", "Org"), ("admin@338", "HackOrg")])
    assert [s[2] for s in spans] == ["admin@338", "organizations"]


def test_locate_spans_normalizes_entity_tokenization():
    # the LLM may return "PlugX." or odd spacing; match against tokenized form
    spans = locate_spans("uses the  Fancy   Bear tool", [("Fancy Bear", "HackOrg")])
    assert spans == [[2, 4, "Fancy Bear", "HackOrg"]]


def test_locate_spans_keeps_abbreviation_period_in_entity():
    spans = locate_spans("targets U.S. agencies .", [("U.S.", "Area")])
    assert spans == [[1, 2, "U.S.", "Area"]]


def test_locate_spans_tolerates_sentence_period_on_entity():
    spans = locate_spans("it uses PlugX .", [("PlugX.", "Tool")])
    assert spans == [[2, 3, "PlugX", "Tool"]]


def test_bio_tags_marks_begin_and_inside():
    assert bio_tags(5, [[1, 3, "Fancy Bear", "HackOrg"], [4, 5, "x", "Tool"]]) == [
        "O", "B-HackOrg", "I-HackOrg", "O", "B-Tool",
    ]


def test_build_relations_fills_every_pair_with_i_greater_than_j():
    rels = build_relations(3, [])
    assert rels == [["noRelation", 1, 0], ["noRelation", 2, 0], ["noRelation", 2, 1]]


def test_build_relations_orders_pairs_by_j_then_i():
    pairs = [(i, j) for _, i, j in build_relations(4, [])]
    assert pairs == [(1, 0), (2, 0), (3, 0), (2, 1), (3, 1), (3, 2)]


def test_build_relations_keeps_label_when_subject_comes_first():
    assert build_relations(2, [(0, "targets", 1)]) == [["targets", 1, 0]]


def test_build_relations_inverts_label_when_subject_comes_second():
    # "PlugX is used by APT28" given as APT28(1) uses PlugX(0)
    assert build_relations(2, [(1, "uses", 0)], inverse=dnrti.inverse) == [["usedBy", 1, 0]]


def test_build_relations_keeps_label_without_inverse():
    assert build_relations(2, [(1, "associatedWith", 0)], inverse=dnrti.inverse) == [["associatedWith", 1, 0]]


def test_build_relations_ignores_self_loops_and_first_label_wins():
    rels = build_relations(2, [(0, "uses", 0), (0, "targets", 1), (0, "uses", 1)])
    assert rels == [["targets", 1, 0]]


def test_format_record_matches_dataset_shape():
    record = format_record(TEXT, [[1, 2, "admin@338", "HackOrg"], [5, 6, "organizations", "Org"]],
                           [(0, "targets", 1)], inverse=dnrti.inverse)
    assert record == {
        "text": TEXT,
        "entities": [[1, 2, "admin@338", "HackOrg"], [5, 6, "organizations", "Org"]],
        "relations": [["targets", 1, 0]],
        "ent_labels": ["O", "B-HackOrg", "O", "O", "O", "B-Org", "O", "O", "O"],
    }


def test_build_record_from_surface_strings():
    record = build_record(
        "The admin@338 has largely targeted organizations with PlugX.",
        [("admin@338", "HackOrg"), ("organizations", "Org"), ("PlugX", "Tool")],
        [("admin@338", "targets", "organizations"), ("admin@338", "uses", "PlugX"),
         ("Unknown", "uses", "PlugX")],
        inverse=dnrti.inverse,
    )
    assert record["text"] == TEXT
    assert record["relations"] == [
        ["targets", 1, 0], ["uses", 2, 0], ["noRelation", 2, 1],
    ]


def test_record_from_tokens_keeps_pretokenized_text_as_is():
    # dataset text may leave punctuation attached; scoring needs the same tokens
    record = record_from_tokens("the (C2) server used by APT28 .", [("APT28", "HackOrg")], [])
    assert record["text"] == "the (C2) server used by APT28 ."
    assert record["entities"] == [[5, 6, "APT28", "HackOrg"]]


# --- v2 schema inverses (the default) -------------------------------------------------

def test_build_relations_uses_schema_inverses_by_default():
    # "X-Agent is used by APT28" given as APT28(1) uses X-Agent(0)
    assert build_relations(2, [(1, "uses", 0)]) == [["used-by", 1, 0]]


def test_build_relations_accepts_inverse_names_from_the_extractor():
    # Malware(0) used-by ThreatGroup(1): already reads left to right
    assert build_relations(2, [(0, "used-by", 1)]) == [["used-by", 1, 0]]
    assert build_relations(2, [(1, "used-by", 0)]) == [["uses", 1, 0]]


def test_build_relations_keeps_symmetric_relation_name():
    assert build_relations(2, [(1, "alias-of", 0)]) == [["alias-of", 1, 0]]


# --- selection filter -----------------------------------------------------------------

V2 = format_record(
    "APT28 used X-Agent to target banks in Germany .",
    [[0, 1, "APT28", "ThreatGroup"], [2, 3, "X-Agent", "Malware"],
     [5, 6, "banks", "Organization"], [7, 8, "Germany", "Location"]],
    [(0, "uses", 1), (0, "targets", 2), (0, "operates-in", 3)],
)


def test_v2_record_matches_the_plan_example():
    assert V2["relations"] == [["uses", 1, 0], ["targets", 2, 0], ["operates-in", 3, 0],
                               ["noRelation", 2, 1], ["noRelation", 3, 1], ["noRelation", 3, 2]]


def test_select_with_nothing_given_keeps_everything():
    assert select(V2) == V2


def test_select_entity_types_removes_entities_and_retags_tokens():
    out = select(V2, entity_types={"ThreatGroup", "Organization", "Location"})
    assert [e[2] for e in out["entities"]] == ["APT28", "banks", "Germany"]
    assert out["ent_labels"][2] == "O"  # X-Agent
    assert out["text"] == V2["text"]


def test_select_entity_types_reindexes_relations():
    out = select(V2, entity_types={"ThreatGroup", "Organization", "Location"})
    assert out["relations"] == [["targets", 1, 0], ["operates-in", 2, 0], ["noRelation", 2, 1]]


def test_select_relation_types_turns_others_into_norelation():
    out = select(V2, relation_types={"targets"})
    assert out["entities"] == V2["entities"]
    assert [r for r in out["relations"] if r[0] != "noRelation"] == [["targets", 2, 0]]


def test_selecting_a_relation_keeps_its_inverse_name():
    rec = format_record("X-Agent is used by APT28 .",
                        [[0, 1, "X-Agent", "Malware"], [4, 5, "APT28", "ThreatGroup"]],
                        [(1, "uses", 0)])
    assert rec["relations"] == [["used-by", 1, 0]]
    assert select(rec, relation_types={"uses"})["relations"] == [["used-by", 1, 0]]
    assert select(rec, relation_types={"used-by"})["relations"] == [["used-by", 1, 0]]


def test_select_with_empty_sets_removes_everything():
    out = select(V2, entity_types=set())
    assert out["entities"] == [] and out["relations"] == [] and set(out["ent_labels"]) == {"O"}


def test_select_works_on_dnrti_records_with_their_inverses():
    rec = format_record("PlugX is used by APT28 against banks .",
                        [[0, 1, "PlugX", "Tool"], [4, 5, "APT28", "HackOrg"], [6, 7, "banks", "Org"]],
                        [(1, "uses", 0), (1, "targets", 2)], inverse=dnrti.inverse)
    out = select(rec, entity_types={"HackOrg", "Org"}, inverse=dnrti.inverse)
    assert out["relations"] == [["targets", 1, 0]]


# --- merging with rule matches ----------------------------------------------------------

def test_locate_spans_skips_tokens_already_taken():
    text = "APT28 used X-Agent against APT28 targets ."
    taken = [[0, 1, "APT28", "ThreatGroup"]]
    assert locate_spans(text, [("APT28", "ThreatActor"), ("X-Agent", "Tool")], taken=taken) == [
        [4, 5, "APT28", "ThreatActor"], [2, 3, "X-Agent", "Tool"]][::-1]


def test_locate_spans_drops_entity_overlapping_a_taken_span():
    text = "the Fancy Bear group"
    assert locate_spans(text, [("Bear group", "ThreatGroup")], taken=[[1, 3, "Fancy Bear", "ThreatGroup"]]) == []

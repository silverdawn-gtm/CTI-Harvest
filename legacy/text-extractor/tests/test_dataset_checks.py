from dataset_checks import record_problems

GOOD = {
    "text": "APT28 uses X-Agent .",
    "entities": [[0, 1, "APT28", "HackOrg"], [2, 3, "X-Agent", "Tool"]],
    "relations": [["uses", 1, 0]],
    "ent_labels": ["B-HackOrg", "O", "B-Tool", "O"],
}


def with_(**changes):
    return {**GOOD, **changes}


def test_clean_record_has_no_problems():
    assert record_problems(GOOD) == []


def test_flags_empty_text():
    assert "empty_text" in record_problems(with_(text="", entities=[], relations=[], ent_labels=[]))


def test_flags_span_past_end_of_text():
    rec = with_(entities=[[0, 1, "APT28", "HackOrg"], [4, 5, "X", "Tool"]])
    assert "span_out_of_range" in record_problems(rec)


def test_flags_surface_not_matching_tokens():
    rec = with_(entities=[[0, 1, "APT28", "HackOrg"], [1, 2, "X-Agent", "Tool"]])
    assert "span_text_mismatch" in record_problems(rec)


def test_flags_labels_length_mismatch():
    assert "labels_length" in record_problems(with_(ent_labels=["O"] * 3))


def test_flags_bio_inconsistent_with_entities():
    rec = with_(ent_labels=["B-HackOrg", "O", "O", "O"])
    assert record_problems(rec) == ["bio_mismatch"]

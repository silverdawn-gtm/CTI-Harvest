import pytest

from eval import entity_scores, relation_scores, relation_triples, sample_test

GOLD = {
    "text": "APT28 uses X-Agent against NATO .",
    "entities": [[0, 1, "APT28", "HackOrg"], [2, 3, "X-Agent", "Tool"], [4, 5, "NATO", "Org"]],
    "relations": [["uses", 1, 0], ["targets", 2, 0], ["noRelation", 2, 1]],
    "ent_labels": ["B-HackOrg", "O", "B-Tool", "O", "B-Org", "O"],
}

PARTIAL = {  # finds APT28 + NATO and the targets link; misses X-Agent
    "text": GOLD["text"],
    "entities": [[0, 1, "APT28", "HackOrg"], [4, 5, "NATO", "Org"]],
    "relations": [["targets", 1, 0]],
    "ent_labels": ["B-HackOrg", "O", "O", "O", "B-Org", "O"],
}


def test_relation_triples_use_typed_spans_and_skip_norelation():
    assert relation_triples(GOLD) == {
        ("uses", (0, 1, "HackOrg"), (2, 3, "Tool")),
        ("targets", (0, 1, "HackOrg"), (4, 5, "Org")),
    }


def test_relation_scores_perfect():
    assert relation_scores([GOLD], [GOLD])["f1"] == 1.0


def test_relation_scores_partial():
    s = relation_scores([GOLD], [PARTIAL])
    assert (s["precision"], s["recall"]) == (1.0, 0.5)
    assert s["f1"] == pytest.approx(2 / 3)


def test_relation_scores_with_no_predictions_is_zero():
    empty = {**PARTIAL, "entities": [], "relations": []}
    assert relation_scores([GOLD], [empty]) == {"precision": 0.0, "recall": 0.0, "f1": 0.0,
                                               "gold": 2, "predicted": 0, "correct": 0}


def test_entity_scores_partial():
    s = entity_scores([GOLD], [PARTIAL])
    assert (s["precision"], s["recall"]) == (1.0, pytest.approx(2 / 3))


def _rec(n, ok=True):
    return {"text": f"t{n} .", "entities": [], "relations": [],
            "ent_labels": ["O", "O"] if ok else ["O"]}


def test_sample_test_skips_noisy_records_and_is_deterministic():
    pool = [_rec(n) for n in range(20)] + [_rec(99, ok=False)]
    a = sample_test(pool, n=10, seed=1)
    assert a == sample_test(pool, n=10, seed=1)
    assert len(a) == 10 and all(r["text"] != "t99 ." for r in a)


def test_sample_test_returns_all_clean_when_n_is_large():
    assert len(sample_test([_rec(n) for n in range(5)], n=100)) == 5

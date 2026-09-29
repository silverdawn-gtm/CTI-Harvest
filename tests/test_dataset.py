"""Checks against the real dataset; skipped until data/dnrti-je.json is present."""
from pathlib import Path

import pytest

from dataset_checks import record_problems
import dnrti
from formatter import format_record
from split_data import load_records
from tokenizer import tokenize

DATASET = Path(__file__).resolve().parent.parent / "data" / "dnrti-je.json"

pytestmark = pytest.mark.skipif(not DATASET.exists(), reason="data/dnrti-je.json not present")


@pytest.fixture(scope="module")
def records():
    return load_records(DATASET)


@pytest.fixture(scope="module")
def clean(records):
    return [r for r in records if not record_problems(r)]


def test_tokenizer_only_inserts_spaces(records):
    bad = [r["text"] for r in records
           if tokenize(r["text"]).replace(" ", "") != "".join(r["text"].split())]
    assert not bad, f"{len(bad)} texts altered, e.g. {bad[:3]}"


def test_tokenizer_leaves_most_dataset_text_unchanged(records):
    # The dataset is inconsistent: ~5% of texts leave "(C2)", "Silence:" etc. attached, and
    # ~3.5% attach a possessive ("APT41's") where it usually writes "APT41 's" (633 vs 336).
    changed = sum(tokenize(r["text"]) != r["text"] for r in records)
    assert changed / len(records) < 0.10


def test_most_records_are_clean(records, clean):
    assert len(clean) / len(records) > 0.93


def test_formatter_rebuilds_every_clean_record(clean):
    bad = []
    for n, r in enumerate(clean):
        triples = [(j, rel, i) for rel, i, j in r["relations"] if rel != "noRelation"]
        if format_record(r["text"], r["entities"], triples, inverse=dnrti.inverse) != r:
            bad.append(n)
    assert not bad, f"{len(bad)} clean records differ, e.g. {[clean[n]['text'][:60] for n in bad[:3]]}"


def test_select_matches_formatting_only_the_selected_items(clean):
    """Filtering a finished record must equal building it from the filtered inputs."""
    from formatter import select
    keep_types, keep_rels = {"HackOrg", "Tool", "Org", "Area"}, {"uses", "targets"}
    bad = 0
    for r in clean[:2000]:
        kept = [k for k, e in enumerate(r["entities"]) if e[3] in keep_types]
        new = {old: n for n, old in enumerate(kept)}
        triples = [(new[j], rel, new[i]) for rel, i, j in r["relations"]
                   if j in new and i in new and dnrti.family(rel) in keep_rels]
        expected = format_record(r["text"], [r["entities"][k] for k in kept], triples, inverse=dnrti.inverse)
        if select(r, keep_types, keep_rels, inverse=dnrti.inverse) != expected:
            bad += 1
    assert bad == 0

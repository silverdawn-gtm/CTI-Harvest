"""Scoring helpers for extraction records (any label set).

Entity F1: seqeval (strict span + label) on ent_labels.
Relation F1: a relation counts only if its label and both typed entity spans match;
noRelation pairs are ignored.

The command-line evaluation over a hand-labelled test set is built in milestone 6.
"""
import random

from seqeval.metrics import f1_score, precision_score, recall_score

from dataset_checks import record_problems


def sample_test(records, n=100, seed=0):
    clean = [r for r in records if not record_problems(r)]
    return random.Random(seed).sample(clean, min(n, len(clean)))


def relation_triples(record):
    ents = record["entities"]
    return {(rel, tuple(ents[j][:2]) + (ents[j][3],), tuple(ents[i][:2]) + (ents[i][3],))
            for rel, i, j in record["relations"] if rel != "noRelation"}


def _prf(correct, predicted, gold):
    p = correct / predicted if predicted else 0.0
    r = correct / gold if gold else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def relation_scores(gold_records, pred_records):
    gold = pred = correct = 0
    for g, p in zip(gold_records, pred_records):
        gt, pt = relation_triples(g), relation_triples(p)
        gold, pred, correct = gold + len(gt), pred + len(pt), correct + len(gt & pt)
    precision, recall, f1 = _prf(correct, pred, gold)
    return {"precision": precision, "recall": recall, "f1": f1,
            "gold": gold, "predicted": pred, "correct": correct}


def relation_scores_by_label(gold_records, pred_records):
    labels = {t[0] for r in gold_records + pred_records for t in relation_triples(r)}
    out = {}
    for label in sorted(labels):
        def only(r):
            return {t for t in relation_triples(r) if t[0] == label}
        gold = sum(len(only(g)) for g in gold_records)
        pred = sum(len(only(p)) for p in pred_records)
        correct = sum(len(only(g) & only(p)) for g, p in zip(gold_records, pred_records))
        p, r, f = _prf(correct, pred, gold)
        out[label] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3), "gold": gold}
    return out


def entity_scores(gold_records, pred_records):
    y_true = [g["ent_labels"] for g in gold_records]
    y_pred = [p["ent_labels"] for p in pred_records]
    return {"precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0)}

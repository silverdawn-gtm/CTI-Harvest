"""Detect annotation errors in dnrti-je records (the dataset is not fully self-consistent).

Usage: python dataset_checks.py [path]   prints a problem summary.
"""
import collections
import sys

from formatter import bio_tags


def record_problems(record):
    tokens = record["text"].split()
    problems = []
    if not tokens:
        problems.append("empty_text")
    for start, end, surface, _ in record["entities"]:
        if end > len(tokens):
            problems.append("span_out_of_range")
        elif " ".join(tokens[start:end]) != surface:
            problems.append("span_text_mismatch")
    if len(record["ent_labels"]) != len(tokens):
        problems.append("labels_length")
    elif not problems and bio_tags(len(tokens), record["entities"]) != record["ent_labels"]:
        problems.append("bio_mismatch")
    return sorted(set(problems))


def main(path="data/dnrti-je.json"):
    from split_data import load_records
    records = load_records(path)
    counts = collections.Counter(p for r in records for p in record_problems(r))
    clean = sum(not record_problems(r) for r in records)
    print(f"{len(records)} records, {clean} clean")
    for problem, n in counts.most_common():
        print(f"  {problem}: {n} records")


if __name__ == "__main__":
    main(*sys.argv[1:])

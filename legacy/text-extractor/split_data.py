"""Split dnrti-je.json into train/dev/test (80/10/10, fixed seed).

Usage: python split_data.py [path]   (default data/dnrti-je.json)
"""
import json
import random
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_records(path):
    content = Path(path).read_text(encoding="utf-8").strip()
    if content.startswith("["):
        return json.loads(content)
    return [json.loads(line) for line in content.splitlines() if line.strip()]


def split_records(records, seed=42):
    shuffled = list(records)
    random.Random(seed).shuffle(shuffled)
    n_train = round(len(shuffled) * 0.8)
    n_dev = round(len(shuffled) * 0.1)
    return shuffled[:n_train], shuffled[n_train:n_train + n_dev], shuffled[n_train + n_dev:]


def main(path=DATA_DIR / "dnrti-je.json"):
    records = load_records(path)
    for name, part in zip(("train", "dev", "test"), split_records(records)):
        out = DATA_DIR / f"{name}.json"
        out.write_text(json.dumps(part, ensure_ascii=False), encoding="utf-8")
        print(f"{name}: {len(part)} records -> {out}")


if __name__ == "__main__":
    main(*sys.argv[1:])

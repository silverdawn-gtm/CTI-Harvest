"""Rule-based entity finder: regex patterns, then dates, then dictionary names.

find(text, types) works on tokenized text and returns
    spans:    [[start, end, surface, type], ...] sorted by position
    triples:  [(i, "alias-of", j), ...] between spans (by index) that are different
              names of the same ATT&CK group
Each token belongs to at most one span; earlier stages win, and dictionary names
match longest first.
"""
import json
from functools import lru_cache
from pathlib import Path

from extractors.patterns import find_times, match_token
from tokenizer import tokenize

DICTIONARY_PATH = Path(__file__).resolve().parent.parent / "dictionaries" / "entities.json"


class RuleMatcher:
    def __init__(self, entries):
        self.exact, self.folded = {}, {}
        for e in entries:
            key = tuple(tokenize(e["name"], split_final_period=False).split())
            if not key:
                continue
            if e.get("case_sensitive", True):
                self.exact.setdefault(key, (e["type"], e["id"]))
            else:
                self.folded.setdefault(tuple(t.lower() for t in key), (e["type"], e["id"]))
        self.max_len = max(map(len, [*self.exact, *self.folded]), default=0)

    def _lookup(self, key):
        return self.exact.get(key) or self.folded.get(tuple(t.lower() for t in key))

    def find(self, text, types=None):
        tokens = text.split()
        wanted = (lambda t: True) if types is None else (lambda t: t in types)
        claimed = [False] * len(tokens)
        found = []  # (start, end, type, id)

        def claim(start, end, type_, id_=None):
            if wanted(type_) and not any(claimed[start:end]):
                claimed[start:end] = [True] * (end - start)
                found.append((start, end, type_, id_))
                return True
            return False

        for i, token in enumerate(tokens):
            type_ = match_token(token)
            if type_:
                claim(i, i + 1, type_)
        for start, end in find_times(tokens):
            claim(start, end, "Time")
        i = 0
        while i < len(tokens):
            for length in range(min(self.max_len, len(tokens) - i), 0, -1):
                hit = self._lookup(tuple(tokens[i:i + length]))
                if hit and claim(i, i + length, *hit):
                    i += length
                    break
            else:
                i += 1

        found.sort()
        spans = [[s, e, " ".join(tokens[s:e]), t] for s, e, t, _ in found]
        triples = [(j, "alias-of", i)
                   for i in range(len(found)) for j in range(i)
                   if found[i][2] == found[j][2] == "ThreatGroup" and found[i][3] == found[j][3]
                   and spans[i][2] != spans[j][2]]
        return spans, triples


@lru_cache(maxsize=None)
def load_matcher(path=DICTIONARY_PATH):
    return RuleMatcher(json.loads(Path(path).read_text(encoding="utf-8")))

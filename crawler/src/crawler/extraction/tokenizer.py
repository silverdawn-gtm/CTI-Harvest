"""Tokenize text into the DNRTI style: space-separated tokens, punctuation split off.

Tokenizing only inserts spaces; it never rewrites a character. Every token is therefore a
substring of the input, in order, which is what lets the pipeline map tokens back to
character offsets.
"""

import re

LEADING = set('"([{“«')
TRAILING = set('",;:!?)]}”»…')
FINAL = TRAILING | {"."}  # a period is only split off the last token of a sentence


def _split_token(token: str, trailing: set[str]) -> list[str]:
    lead, tail = [], []
    while len(token) > 1 and token[0] in LEADING:
        lead.append(token[0])
        token = token[1:]
    while len(token) > 1 and token[-1] in trailing:
        tail.insert(0, token[-1])
        token = token[:-1]
    possessive = re.fullmatch(r"(.+)(['’]s)", token)
    if possessive:
        return lead + [possessive.group(1), possessive.group(2)] + tail
    return lead + [token] + tail


def tokenize(text: str, split_final_period: bool = True) -> str:
    words = text.split()
    tokens = []
    for n, word in enumerate(words):
        last = split_final_period and n == len(words) - 1
        tokens.extend(_split_token(word, FINAL if last else TRAILING))
    return " ".join(tokens)


ABBREVIATIONS = {
    "e.g.", "i.e.", "etc.", "vs.", "cf.", "al.", "approx.", "no.", "fig.", "inc.", "ltd.",
    "corp.", "co.", "mr.", "ms.", "dr.", "u.s.", "u.k.", "e.u.", "u.n.",
    "jan.", "feb.", "mar.", "apr.", "jun.", "jul.", "aug.", "sep.", "sept.", "oct.", "nov.",
    "dec.",
}  # fmt: skip


def _ends_sentence(before: str, after: str) -> bool:
    """Whether a [.!?] at the end of `before` ends the sentence, given the text `after` it."""
    if after[:1].islower():
        return False
    last = before.split()[-1].lower() if before.split() else ""
    return last not in ABBREVIATIONS and not re.fullmatch(r"[a-z]\.", last)


def split_sentences(text: str) -> list[str]:
    text = text.strip()
    sentences: list[str] = []
    start = 0
    for gap in re.finditer(r"(?<=[.!?])\s+", text):
        if _ends_sentence(text[start : gap.start()], text[gap.end() :]):
            sentences.append(text[start : gap.start()])
            start = gap.end()
    sentences.append(text[start:])
    return [s for s in sentences if s]

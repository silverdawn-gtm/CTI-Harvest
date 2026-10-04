"""Place extracted entity strings on tokens, and tokens on characters.

The LLM answers with entity *strings* and (source, relation, target) string triples;
everything positional is computed here.
"""

from collections.abc import Iterable, Iterator, Sequence

from crawler.extraction.spans import Entity, IndexTriple, Span, SurfaceTriple
from crawler.extraction.tokenizer import tokenize

PUNCT = set('.,;:!?"()[]{}')


def _entity_tokens(surface: str) -> list[str]:
    tokens = tokenize(surface, split_final_period=False).split()
    while tokens and tokens[-1] in PUNCT:
        tokens.pop()
    while tokens and tokens[0] in PUNCT:
        tokens.pop(0)
    return tokens


def _candidates(surface: str) -> Iterator[list[str]]:
    """The entity's tokens, then (for "PlugX.") the same without a trailing period."""
    tokens = _entity_tokens(surface)
    yield tokens
    if tokens and len(tokens[-1]) > 1 and tokens[-1].endswith("."):
        yield tokens[:-1] + [tokens[-1][:-1]]


def _find(
    tokens: Sequence[str], used: Sequence[bool], needle: Sequence[str]
) -> tuple[int, int] | None:
    for start in range(len(tokens) - len(needle) + 1):
        end = start + len(needle)
        if list(tokens[start:end]) == list(needle) and not any(used[start:end]):
            return start, end
    return None


def locate_spans(text: str, entities: Iterable[Entity], taken: Iterable[Span] = ()) -> list[Span]:
    """Map (surface, type) pairs to [start, end, surface, type] spans in tokenized `text`.

    Repeated strings take the next unused occurrence. Entities not found, or overlapping an
    already placed span or one in `taken`, are dropped.
    """
    tokens = text.split()
    used = [False] * len(tokens)
    for start, end, *_ in taken:
        used[start:end] = [True] * (end - start)
    spans: list[Span] = []
    for surface, label in entities:
        for needle in _candidates(surface):
            found = _find(tokens, used, needle) if needle else None
            if found:
                start, end = found
                used[start:end] = [True] * len(needle)
                spans.append([start, end, " ".join(needle), label])
                break
    return sorted(spans, key=lambda s: s[0])


def resolve_triples(spans: Sequence[Span], triples: Iterable[SurfaceTriple]) -> list[IndexTriple]:
    """Turn (source_text, relation, target_text) into span indices.

    A text refers to the first span with that surface. Triples naming a text that is not
    among the spans are dropped.
    """
    index: dict[str, int] = {}
    for n, span in enumerate(spans):
        index.setdefault(span[2], n)

    def lookup(surface: str) -> int | None:
        return next((index[k] for k in map(" ".join, _candidates(surface)) if k in index), None)

    resolved: list[IndexTriple] = []
    for subj, rel, obj in triples:
        s, o = lookup(subj), lookup(obj)
        if s is not None and o is not None:
            resolved.append((s, rel, o))
    return resolved


def token_offsets(sentence: str, tokens: Sequence[str]) -> list[tuple[int, int]]:
    """Character [start, end) of each token in `sentence`.

    tokenize() only inserts spaces, so every token is found, in order, by scanning forward
    from the end of the previous one.
    """
    out: list[tuple[int, int]] = []
    cursor = 0
    for token in tokens:
        start = sentence.find(token, cursor)
        if start < 0:
            raise ValueError(f"token {token!r} not found in sentence after offset {cursor}")
        end = start + len(token)
        out.append((start, end))
        cursor = end
    return out

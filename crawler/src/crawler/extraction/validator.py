"""Enforce the ontology on merged rule + LLM output.

validate(spans, triples, ontology) -> (spans, triples, dropped)
Spans whose type the ontology lacks are removed and the survivors reindexed. Triples are
rewritten into the stored direction ("used-by" becomes "uses" with source and target swapped),
deduplicated, and kept only if the ontology allows (source type, relation, target type).
`dropped` explains, for the output file's audit trail, every span removed for an unknown type,
every triple removed for an unknown relation, and every triple the ontology disallows.
Self-loops, duplicates and triples whose endpoint span was removed are dropped silently.
"""

from collections.abc import Iterable, Sequence

from crawler.extraction.ontology import Ontology
from crawler.extraction.spans import IndexTriple, Span


def validate(
    spans: Sequence[Span], triples: Iterable[IndexTriple], ontology: Ontology
) -> tuple[list[Span], list[IndexTriple], list[str]]:
    known = set(ontology.entity_names)
    dropped: list[str] = []

    kept: list[Span] = []
    new_index: dict[int, int] = {}
    for n, span in enumerate(spans):
        if span[3] in known:
            new_index[n] = len(kept)
            kept.append(span)
        else:
            dropped.append(f"{span[2]}: unknown entity type {span[3]}")

    out: list[IndexTriple] = []
    seen: set[IndexTriple] = set()
    for src, relation, tgt in triples:
        if src not in new_index or tgt not in new_index or src == tgt:
            continue
        src, tgt = new_index[src], new_index[tgt]
        name, flipped = ontology.canonical(relation)
        if name is None:
            dropped.append(f"{relation}: unknown relation")
            continue
        if flipped:
            src, tgt = tgt, src
        s_type, t_type = kept[src][3], kept[tgt][3]
        if not ontology.allowed(s_type, name, t_type):
            dropped.append(
                f"{kept[src][2]} {name} {kept[tgt][2]}: "
                f"ontology does not allow {s_type} {name} {t_type}"
            )
            continue
        triple = (src, name, tgt)
        if triple not in seen:
            seen.add(triple)
            out.append(triple)
    return kept, out, dropped

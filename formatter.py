"""The single source of truth for the dnrti-je output format.

Extractors only return entity strings and (subject, relation, object) triples;
everything index-related is computed here. Relation names are flipped with an
`inverse` function: the schema's (schema/schema.json) by default, or dnrti.inverse
for DNRTI labels.
"""
from ontology import load_schema
from tokenizer import tokenize


def schema_inverse(relation):
    try:
        return load_schema().inverse(relation)
    except KeyError:
        return relation

PUNCT = set('.,;:!?"()[]{}')


def _entity_tokens(surface):
    tokens = tokenize(surface, split_final_period=False).split()
    while tokens and tokens[-1] in PUNCT:
        tokens.pop()
    while tokens and tokens[0] in PUNCT:
        tokens.pop(0)
    return tokens


def _candidates(surface):
    """The entity's tokens, then (for "PlugX.") the same without a trailing period."""
    tokens = _entity_tokens(surface)
    yield tokens
    if tokens and len(tokens[-1]) > 1 and tokens[-1].endswith("."):
        yield tokens[:-1] + [tokens[-1][:-1]]


def _find(tokens, used, needle):
    for start in range(len(tokens) - len(needle) + 1):
        end = start + len(needle)
        if tokens[start:end] == needle and not any(used[start:end]):
            return start, end
    return None


def locate_spans(text, entities, taken=()):
    """Map (surface, label) pairs to [start, end, surface, label] spans, sorted by start.

    Repeated strings take the next unused occurrence; entities not found, or
    overlapping an already placed one or a span in `taken`, are dropped.
    """
    tokens = text.split()
    used = [False] * len(tokens)
    for start, end, *_ in taken:
        used[start:end] = [True] * (end - start)
    spans = []
    for surface, label in entities:
        for needle in _candidates(surface):
            found = needle and _find(tokens, used, needle)
            if found:
                start, end = found
                used[start:end] = [True] * len(needle)
                spans.append([start, end, " ".join(needle), label])
                break
    return sorted(spans, key=lambda s: s[0])


def bio_tags(n_tokens, spans):
    tags = ["O"] * n_tokens
    for start, end, _, label in spans:
        tags[start] = f"B-{label}"
        for k in range(start + 1, end):
            tags[k] = f"I-{label}"
    return tags


def build_relations(n_entities, triples, inverse=schema_inverse):
    """Return [rel, i, j] for every pair i > j (ordered by j, then i), read as j -> rel -> i.

    `triples` are (subject_index, relation, object_index). When the subject comes
    after the object, the inverse label is used. First label wins.
    """
    pair_rel = {}
    for subj, rel, obj in triples:
        if subj == obj:
            continue
        if subj < obj:
            key = (obj, subj)
        else:
            key, rel = (subj, obj), inverse(rel)
        pair_rel.setdefault(key, rel)
    return [[pair_rel.get((i, j), "noRelation"), i, j]
            for j in range(n_entities) for i in range(j + 1, n_entities)]


def format_record(text, spans, triples, inverse=schema_inverse):
    return {
        "text": text,
        "entities": spans,
        "relations": build_relations(len(spans), triples, inverse),
        "ent_labels": bio_tags(len(text.split()), spans),
    }


def build_record(sentence, entities, triples, inverse=schema_inverse):
    """Build a record from raw text, (surface, label) entities and (subj, rel, obj) surface triples."""
    return record_from_tokens(tokenize(sentence), entities, triples, inverse)


def record_from_tokens(text, entities, triples, inverse=schema_inverse):
    """Like build_record, but `text` is already tokenized and kept exactly as given."""
    spans = locate_spans(text, entities)
    return format_record(text, spans, resolve_triples(spans, triples), inverse)


def resolve_triples(spans, triples):
    """Turn (subject_text, rel, object_text) into (subject_index, rel, object_index).

    A text refers to the first span with that surface; triples naming a text that
    is not among the spans are dropped.
    """
    index = {}
    for n, span in enumerate(spans):
        index.setdefault(span[2], n)

    def lookup(surface):
        return next((index[k] for k in map(" ".join, _candidates(surface)) if k in index), None)

    resolved = []
    for subj, rel, obj in triples:
        s, o = lookup(subj), lookup(obj)
        if s is not None and o is not None:
            resolved.append((s, rel, o))
    return resolved


def select(record, entity_types=None, relation_types=None, inverse=schema_inverse):
    """Keep only the selected entity and relation types (None keeps all).

    Unselected entities are removed and their tokens tagged O; relation indices are
    renumbered. Unselected relations become noRelation. Selecting a relation by
    either name keeps both its names.
    """
    entities = record["entities"]
    kept = [k for k, e in enumerate(entities) if entity_types is None or e[3] in entity_types]
    new_index = {old: new for new, old in enumerate(kept)}
    if relation_types is not None:
        relation_types = set(relation_types) | {inverse(r) for r in relation_types}
    triples = [(new_index[j], rel, new_index[i]) for rel, i, j in record["relations"]
               if rel != "noRelation" and i in new_index and j in new_index
               and (relation_types is None or rel in relation_types)]
    return format_record(record["text"], [entities[k] for k in kept], triples, inverse)

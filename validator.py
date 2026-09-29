"""Enforce schema/schema.json on extracted entities and relations.

validate(spans, triples, entity_types, relation_types) -> (spans, triples, dropped)
    spans:   [[start, end, surface, type], ...]
    triples: [(source_index, relation, target_index), ...] indexing into spans
Returned triples use the stored relation name and direction; the formatter picks
the inverse name when the source comes later in the sentence. `dropped` lists
everything removed, as {"item": ..., "reason": ...}.
"""
from ontology import load_schema


def validate(spans, triples, entity_types, relation_types=None, schema=None):
    schema = schema or load_schema()
    known = {t.name for t in schema.entity_types}
    dropped = []

    kept, new_index = [], {}
    for n, span in enumerate(spans):
        if span[3] not in known:
            dropped.append({"item": span[2], "reason": f"unknown entity type {span[3]}"})
        elif span[3] not in entity_types:
            dropped.append({"item": span[2], "reason": f"entity type {span[3]} not selected"})
        else:
            new_index[n] = len(kept)
            kept.append(span)

    available = schema.relations_for(set(entity_types), relation_types)
    out, seen = [], set()
    for src, relation, tgt in triples:
        if src not in new_index or tgt not in new_index or src == tgt:
            continue
        src, tgt = new_index[src], new_index[tgt]
        name, flipped = schema.canonical(None, relation, None)
        if name is None:
            dropped.append({"item": relation, "reason": f"unknown relation {relation}"})
            continue
        if flipped:
            src, tgt = tgt, src
        s_type, t_type = kept[src][3], kept[tgt][3]
        label = f"{kept[src][2]} {name} {kept[tgt][2]}"
        if relation_types is not None and name not in relation_types and schema.inverse(name) not in relation_types:
            reason = f"relation {name} not selected"
        elif not schema.allowed(s_type, name, t_type):
            reason = f"schema does not allow {s_type} {name} {t_type}"
        elif (s_type, t_type) not in available.get(name, []):
            reason = f"generic {name} not used: a more specific relation fits {s_type} -> {t_type}"
        else:
            if (src, name, tgt) not in seen:
                seen.add((src, name, tgt))
                out.append((src, name, tgt))
            continue
        dropped.append({"item": label, "reason": reason})
    return kept, out, dropped

"""Schema-driven LLM extractor (v2): prompt building, JSON parsing and retries.

The prompt and the JSON response schema are generated from schema/schema.json for
the selected entity types. Provider wrappers (gemini.py, mistral.py) supply
complete(prompt, response_schema=None) -> str.

extract(sentence, entity_types, relation_types=None, known=()) returns
    entities: [(text, type), ...]                 new entities only
    triples:  [(source_text, relation, target_text), ...]
`known` are spans the rules already found; the LLM may use them in relations.
"""
import json
from pathlib import Path

from ontology import load_schema

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"
PROMPT_PATH = PROMPTS / "extract_v2.txt"
EXAMPLES_PATH = PROMPTS / "examples_v2.json"


def filter_example(example, entity_types, relations):
    entities = [e for e in example["entities"] if e["type"] in entity_types]
    types = {e["text"]: e["type"] for e in entities}
    kept = [r for r in example["relations"]
            if r["source"] in types and r["target"] in types
            and (types[r["source"]], types[r["target"]]) in relations.get(r["relation"], [])]
    return {"text": example["text"], "entities": entities, "relations": kept}


def build_prompt(sentence, entity_types, relation_types=None, known=(), examples=None, schema=None):
    schema = schema or load_schema()
    relations = schema.relations_for(entity_types, relation_types)
    types = [t for t in schema.entity_types if t.name in entity_types]
    if examples is None:
        examples = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))

    type_lines = "\n".join(f"- {t.name}: {t.description}" for t in types)
    descriptions = {r.name: r.description for r in schema.relations}
    relation_lines = "\n".join(
        f"- {name}: {', '.join(f'{s} -> {t}' for s, t in pairs)}  ({descriptions[name]})"
        for name, pairs in relations.items()
    ) or "(none selected) Do not output relations; return an empty relations list."
    known_lines = "\n".join(f'- "{s[2]}" ({s[3]})' for s in known) or "(none)"
    shots = []
    for example in examples:
        ex = filter_example(example, entity_types, relations)
        if ex["entities"]:
            output = {"entities": ex["entities"], "relations": ex["relations"]}
            shots.append(f"Sentence: {ex['text']}\nOutput: {json.dumps(output, ensure_ascii=False)}")

    template = PROMPT_PATH.read_text(encoding="utf-8")
    for key, value in [("{entity_types}", type_lines), ("{relations}", relation_lines),
                       ("{known}", known_lines), ("{examples}", "\n\n".join(shots) or "(none)"),
                       ("{sentence}", sentence)]:
        template = template.replace(key, value)
    return template


def response_schema(entity_types, relations, schema=None):
    schema = schema or load_schema()
    names = sorted({n for r in relations for n in (r, schema.inverse(r))})
    relation_item = {"type": "string", "enum": names} if names else {"type": "string"}
    return {
        "type": "object",
        "properties": {
            "entities": {"type": "array", "items": {
                "type": "object",
                "properties": {"text": {"type": "string"},
                               "type": {"type": "string", "enum": sorted(entity_types)}},
                "required": ["text", "type"],
            }},
            "relations": {"type": "array", "items": {
                "type": "object",
                "properties": {"source": {"type": "string"}, "relation": relation_item,
                               "target": {"type": "string"}},
                "required": ["source", "relation", "target"],
            }},
        },
        "required": ["entities", "relations"],
    }


def parse_response(raw, entity_types, relation_names, known_texts=()):
    """Parse and filter a JSON reply. Raises ValueError if it is unusable."""
    try:
        data = json.loads(raw)
        entities = [(str(e["text"]), e["type"]) for e in data["entities"]]
        triples = [(str(r["source"]), r["relation"], str(r["target"])) for r in data["relations"]]
    except (json.JSONDecodeError, KeyError, TypeError) as err:
        raise ValueError(f"unusable reply: {err}") from err
    entities = [(t, ty) for t, ty in entities if ty in entity_types and t.strip()]
    texts = {t for t, _ in entities} | set(known_texts)
    triples = [(s, r, o) for s, r, o in triples if r in relation_names and s in texts and o in texts]
    return entities, triples


class SchemaLLMExtractor:
    def __init__(self, complete, examples=None):
        self.complete = complete
        self.examples = examples

    def extract(self, sentence, entity_types, relation_types=None, known=()):
        if not entity_types:
            return [], []
        schema = load_schema()
        relations = schema.relations_for(entity_types, relation_types)
        names = {n for r in relations for n in (r, schema.inverse(r))}
        prompt = build_prompt(sentence, entity_types, relation_types, known, self.examples)
        json_schema = response_schema(entity_types, relations)
        for _ in range(2):
            try:
                raw = self.complete(prompt, response_schema=json_schema)
                return parse_response(raw, entity_types, names, known_texts={s[2] for s in known})
            except ValueError:
                continue
        return [], []

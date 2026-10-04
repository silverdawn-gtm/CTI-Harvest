"""Schema-constrained LLM pass.

The ontology becomes two things: a prompt that describes it, and a JSON Schema that the
provider enforces while decoding (structured outputs). The schema enumerates entity types
and, for relations, one branch per (relation, source type) listing the permitted target
types, so a triple the ontology lacks cannot be produced. parse_response still checks every
reply: the schema cannot know which *strings* are entities of which type.
"""

import json
from collections.abc import Awaitable, Callable, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from crawler.extraction.ontology import Ontology
from crawler.extraction.spans import Entity, Span, SurfaceTriple

RESOURCES = Path(__file__).resolve().parent / "resources"
PROMPT_PATH = RESOURCES / "extract.txt"
EXAMPLES_PATH = RESOURCES / "examples.json"

# complete(prompt, json_schema) -> the model's raw JSON reply
Complete = Callable[[str, dict[str, Any]], Awaitable[str]]


def load_examples(path: Path = EXAMPLES_PATH) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _template() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _shot(example: dict[str, Any], ontology: Ontology) -> str | None:
    """One few-shot example in the reply format, keeping only what the ontology allows."""
    names = set(ontology.entity_names)
    types = {e["text"]: e["type"] for e in example["entities"] if e["type"] in names}
    if not types:
        return None
    relations = [
        {
            "source": r["source"],
            "source_type": types[r["source"]],
            "relation": r["relation"],
            "target": r["target"],
            "target_type": types[r["target"]],
        }
        for r in example["relations"]
        if r["source"] in types
        and r["target"] in types
        and (types[r["source"]], types[r["target"]])
        in ontology.allowed_pairs.get(r["relation"], ())
    ]
    output = {
        "entities": [{"text": t, "type": ty} for t, ty in types.items()],
        "relations": relations,
    }
    return f"Sentence: {example['text']}\nOutput: {json.dumps(output, ensure_ascii=False)}"


def build_prompt(
    sentence: str,
    ontology: Ontology,
    known: Sequence[Span] = (),
    examples: Sequence[dict[str, Any]] | None = None,
) -> str:
    if examples is None:
        examples = load_examples()
    type_lines = "\n".join(f"- {t.name}: {t.description}" for t in ontology.entity_types)
    descriptions = {r.name: r.description for r in ontology.relations}
    relation_lines = "\n".join(
        f"- {name}: {', '.join(f'{s} -> {t}' for s, t in pairs)}  ({descriptions[name]})"
        for name, pairs in ontology.allowed_pairs.items()
        if pairs
    )
    known_lines = "\n".join(f'- "{s[2]}" ({s[3]})' for s in known) or "(none)"
    shots = [shot for example in examples if (shot := _shot(example, ontology))]

    prompt = _template()
    for key, value in (
        ("{entity_types}", type_lines),
        ("{relations}", relation_lines),
        ("{known}", known_lines),
        ("{examples}", "\n\n".join(shots) or "(none)"),
        ("{sentence}", sentence),
    ):
        prompt = prompt.replace(key, value)
    return prompt


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def response_schema(ontology: Ontology) -> dict[str, Any]:
    branches: list[dict[str, Any]] = []
    for relation, pairs in ontology.allowed_pairs.items():
        targets_by_source: dict[str, list[str]] = {}
        for source_type, target_type in pairs:
            targets_by_source.setdefault(source_type, []).append(target_type)
        for source_type, targets in targets_by_source.items():
            branches.append(
                _object(
                    {
                        "source": {"type": "string"},
                        "source_type": {"type": "string", "enum": [source_type]},
                        "relation": {"type": "string", "enum": [relation]},
                        "target": {"type": "string"},
                        "target_type": {"type": "string", "enum": targets},
                    }
                )
            )

    entity = _object(
        {
            "text": {"type": "string"},
            "type": {"type": "string", "enum": list(ontology.entity_names)},
        }
    )
    return _object(
        {
            "entities": {"type": "array", "items": entity},
            "relations": {"type": "array", "items": {"anyOf": branches}},
        }
    )


def parse_response(
    raw: str, ontology: Ontology, known: Sequence[Span] = ()
) -> tuple[list[Entity], list[SurfaceTriple]]:
    """Read a structured reply. Raises ValueError if it is not the expected shape.

    Entities of unknown types are dropped. A relation survives only if the ontology allows
    it and both its ends are entities, new or already found, of exactly the types it claims.
    """
    try:
        data = json.loads(raw)
        entities = [(str(e["text"]), str(e["type"])) for e in data["entities"]]
        relations = [
            (
                str(r["source"]),
                str(r["source_type"]),
                str(r["relation"]),
                str(r["target"]),
                str(r["target_type"]),
            )
            for r in data["relations"]
        ]
    except (json.JSONDecodeError, KeyError, TypeError) as err:
        raise ValueError(f"unusable reply: {err}") from err

    names = set(ontology.entity_names)
    entities = [(text, type_) for text, type_ in entities if type_ in names and text.strip()]
    typed = {(s[2], s[3]) for s in known} | set(entities)
    triples = [
        (src, rel, tgt)
        for src, src_type, rel, tgt, tgt_type in relations
        if (src_type, tgt_type) in ontology.allowed_pairs.get(rel, ())
        and (src, src_type) in typed
        and (tgt, tgt_type) in typed
    ]
    return entities, triples


class LLMExtractor:
    """One tokenized sentence in; new entities and relation triples out, held to the ontology."""

    def __init__(
        self,
        complete: Complete,
        ontology: Ontology,
        examples: Sequence[dict[str, Any]] | None = None,
        attempts: int = 2,
    ) -> None:
        self.complete = complete
        self.ontology = ontology
        self.examples = load_examples() if examples is None else list(examples)
        self.schema = response_schema(ontology)
        self.attempts = attempts

    @property
    def model_name(self) -> str | None:
        return getattr(self.complete, "last_model", None)

    async def extract(
        self, sentence: str, known: Sequence[Span] = ()
    ) -> tuple[list[Entity], list[SurfaceTriple]]:
        prompt = build_prompt(sentence, self.ontology, known, self.examples)
        error: ValueError | None = None
        for _ in range(self.attempts):
            raw = await self.complete(prompt, self.schema)
            try:
                return parse_response(raw, self.ontology, known)
            except ValueError as exc:
                error = exc
        raise ValueError(f"no usable reply after {self.attempts} attempts: {error}")

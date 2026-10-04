"""The CTI ontology: which entity types exist and which relations may join them.

config/ontology.json is the single source of truth. The LLM's response schema, its prompt and
the validator that runs afterwards are all generated from one loaded Ontology, so the extractor
cannot emit a type or a triple the file does not list.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TYPE_NAME = r"^[A-Z][A-Za-z0-9]{1,39}$"  # becomes a BIO-style label, so one word
RELATION_NAME = r"^[a-z][a-z0-9_-]{1,39}$"


class OntologyError(ValueError):
    """config/ontology.json is missing, malformed, or internally inconsistent."""


class _EntityTypeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=TYPE_NAME)
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)


class _RelationFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=RELATION_NAME)
    inverse: str = Field(pattern=RELATION_NAME)
    description: str = Field(min_length=1)
    pairs: list[tuple[str, str]] = []
    generic_target: str | None = None


class _OntologyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1)
    entity_types: list[_EntityTypeFile] = Field(min_length=1)
    relations: list[_RelationFile]


@dataclass(frozen=True)
class EntityType:
    name: str
    label: str
    description: str


@dataclass(frozen=True)
class Relation:
    name: str
    inverse: str
    description: str
    pairs: frozenset[tuple[str, str]]
    generic_target: str | None = None


class Ontology:
    def __init__(
        self,
        version: str,
        entity_types: Sequence[EntityType],
        relations: Sequence[Relation],
    ) -> None:
        self.version = version
        self.entity_types = tuple(entity_types)
        self.relations = tuple(relations)
        self.entity_names = tuple(t.name for t in self.entity_types)
        self._forward = {r.name: r for r in self.relations}
        self._inverse = {r.inverse: r for r in self.relations if r.inverse != r.name}
        self.allowed_pairs = self._expand()

    def _expand(self) -> dict[str, list[tuple[str, str]]]:
        """{relation: [(source, target), ...]} with every generic rule spelled out.

        "Any entity -> located-in -> Location" applies only to source types with no specific
        relation to Location: a group has operates-in, so "APT28 located-in Russia" is not
        offered and "APT28 operates-in Russia" is.
        """
        order = {name: n for n, name in enumerate(self.entity_names)}
        specific = {pair for r in self.relations for pair in r.pairs}
        out: dict[str, list[tuple[str, str]]] = {}
        for r in self.relations:
            pairs = set(r.pairs)
            if r.generic_target is not None:
                pairs |= {
                    (s, r.generic_target)
                    for s in self.entity_names
                    if s != r.generic_target and (s, r.generic_target) not in specific
                }
            out[r.name] = sorted(pairs, key=lambda p: (order[p[0]], order[p[1]]))
        return out

    def canonical(self, relation: str) -> tuple[str | None, bool]:
        """(stored name, flipped). `flipped` means the caller's source and target swap."""
        if relation in self._forward:
            return relation, False
        if relation in self._inverse:
            return self._inverse[relation].name, True
        return None, False

    def allowed(self, source_type: str, relation: str, target_type: str) -> bool:
        name, flipped = self.canonical(relation)
        if name is None:
            return False
        if flipped:
            source_type, target_type = target_type, source_type
        return (source_type, target_type) in self.allowed_pairs[name]


def parse_ontology(data: object, source: str = "ontology.json") -> Ontology:
    try:
        parsed = _OntologyFile.model_validate(data)
    except ValidationError as exc:
        raise OntologyError(f"{source}: {exc}") from exc

    names = [t.name for t in parsed.entity_types]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise OntologyError(f"{source}: duplicate entity type {', '.join(dupes)}")
    known = set(names)

    taken: set[str] = set()
    relations: list[Relation] = []
    for r in parsed.relations:
        words = {r.name, r.inverse}
        clash = sorted(words & taken)
        if clash:
            raise OntologyError(f"{source}: relation name {', '.join(clash)} is used twice")
        taken |= words

        unknown = sorted({t for pair in r.pairs for t in pair} - known)
        if r.generic_target is not None and r.generic_target not in known:
            unknown.append(r.generic_target)
        if unknown:
            raise OntologyError(
                f"{source}: relation {r.name} names unknown entity type {', '.join(unknown)}"
            )
        if not r.pairs and r.generic_target is None:
            raise OntologyError(f"{source}: relation {r.name} allows no pairs")

        relations.append(
            Relation(r.name, r.inverse, r.description, frozenset(r.pairs), r.generic_target)
        )

    types = [EntityType(t.name, t.label, t.description) for t in parsed.entity_types]
    return Ontology(parsed.version, types, relations)


@cache
def load_ontology(path: Path) -> Ontology:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise OntologyError(f"{path}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise OntologyError(f"{path}: not valid JSON ({exc})") from exc
    return parse_ontology(data, str(path))

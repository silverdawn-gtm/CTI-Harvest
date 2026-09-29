"""Load the entity/relation schema: schema/schema.json (from the PDF) merged with the
user's custom overlay schema/custom.json.

Type arguments are BIO names ("ThreatGroup"); relation arguments may be a stored
name ("uses") or its inverse ("used-by").
"""
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
SCHEMA_PATH = SCHEMA_DIR / "schema.json"
CUSTOM_PATH = SCHEMA_DIR / "custom.json"   # read at call time, so tests can point it elsewhere
CUSTOM_GROUP = "Custom"
CUSTOM_ID_START = 101
TYPE_NAME = re.compile(r"[A-Z][A-Za-z0-9]{1,39}")      # becomes a BIO label, so one word
RELATION_NAME = re.compile(r"[a-z][a-z0-9-]{1,39}")


class CustomFileError(ValueError):
    """A schema file could not be read."""


@dataclass(frozen=True)
class EntityType:
    id: int
    name: str
    label: str
    group: str
    description: str


@dataclass(frozen=True)
class Relation:
    name: str
    inverse: str
    pairs: frozenset          # {(source_type, target_type)} by BIO name
    generic_target: str = None  # "any entity -> this type"
    description: str = ""


@dataclass
class Schema:
    entity_types: list
    relations: list
    assumptions: list = field(default_factory=list)
    presets: dict = field(default_factory=dict)
    custom_names: frozenset = frozenset()   # custom entity types and relation names

    def __post_init__(self):
        self._by_id = {t.id: t for t in self.entity_types}
        self._names = {t.name for t in self.entity_types}
        self._forward = {r.name: r for r in self.relations}
        self._inverse = {r.inverse: r for r in self.relations if r.inverse != r.name}

    def type_name(self, type_id):
        return self._by_id[type_id].name

    def is_custom(self, name):
        return name in self.custom_names

    def inverse(self, relation):
        if relation in self._forward:
            return self._forward[relation].inverse
        return self._inverse[relation].name

    def canonical(self, source, relation, target):
        """Return (stored relation name, flipped) where flipped means source/target swap."""
        if relation in self._forward:
            return relation, False
        if relation in self._inverse:
            return self._inverse[relation].name, True
        return None, False

    def _matches(self, rel, source, target):
        return (source, target) in rel.pairs, rel.generic_target == target

    def allowed(self, source, relation, target):
        if source not in self._names or target not in self._names:
            return False
        name, flipped = self.canonical(source, relation, target)
        if name is None:
            return False
        if flipped:
            source, target = target, source
        specific, generic = self._matches(self._forward[name], source, target)
        return specific or generic

    def is_generic(self, relation, source, target):
        """True if the triple is allowed only through an 'any entity ->' rule."""
        name, flipped = self.canonical(source, relation, target)
        if flipped:
            source, target = target, source
        specific, generic = self._matches(self._forward[name], source, target)
        return generic and not specific

    def specific_triples(self):
        ids = {t.name: t.id for t in self.entity_types}
        return {(ids[s], r.name, ids[t]) for r in self.relations for s, t in r.pairs}

    def relations_for(self, entity_types, relation_types=None):
        """{relation: [(source, target), ...]} usable between the selected entity types.

        A generic "any entity -> target" relation is expanded to the selected sources
        that have no selected specific relation to that target. Relations may be
        selected by either name; None selects all.
        """
        chosen = [r for r in self.relations if relation_types is None
                  or r.name in relation_types or r.inverse in relation_types]
        order = {t.name: t.id for t in self.entity_types}
        selected = sorted((t for t in entity_types if t in order), key=order.get)
        specific = {(s, t) for r in chosen for s, t in r.pairs}
        out = {}
        for r in chosen:
            pairs = [(s, t) for s in selected for t in selected if (s, t) in r.pairs]
            if r.generic_target in selected:
                pairs += [(s, r.generic_target) for s in selected
                          if s != r.generic_target and (s, r.generic_target) not in specific]
            if pairs:
                out[r.name] = sorted(set(pairs), key=lambda p: (order[p[0]], order[p[1]]))
        return out


def read_json(path):
    # names only in messages: the full path would reveal the user's folder to remote callers
    name = Path(path).name
    try:
        # utf-8-sig: PowerShell 5.1 writes UTF-8 with a byte-order mark
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except UnicodeDecodeError as err:
        raise CustomFileError(f"{name} is not UTF-8 text; save it as UTF-8, or fix or delete it") from err
    except json.JSONDecodeError as err:
        raise CustomFileError(f"{name} is not valid JSON ({err}); fix or delete it") from err


def _is_text(item, *keys):
    return isinstance(item, dict) and all(isinstance(item.get(k), str) for k in keys)


def check_custom(data, source="custom.json"):
    """Check the shape of a custom overlay (hand-edited files included); return its two lists."""
    def fail(problem):
        raise CustomFileError(f"{source}: {problem}; fix or delete it")

    if not isinstance(data, dict):
        fail("must be a JSON object with entity_types and relations lists")
    out = {}
    for key in ("entity_types", "relations"):
        out[key] = data.get(key, [])
        if not isinstance(out[key], list):
            fail(f"{key} must be a list")
    for i, t in enumerate(out["entity_types"]):
        if not (_is_text(t, "name", "label", "description") and TYPE_NAME.fullmatch(t["name"])):
            fail(f"entity_types[{i}] needs a name (one capitalised word), a label and a description")
    for i, r in enumerate(out["relations"]):
        pairs = r.get("pairs") if isinstance(r, dict) else None
        if not (_is_text(r, "name", "inverse", "description")
                and RELATION_NAME.fullmatch(r["name"]) and RELATION_NAME.fullmatch(r["inverse"])
                and isinstance(pairs, list)
                and all(isinstance(p, list) and len(p) == 2 and all(isinstance(x, str) for x in p) for p in pairs)):
            fail(f"relations[{i}] needs a name and inverse (lowercase with hyphens), a description "
                 f"and a list of [source, target] pairs")
    return out


def _build(data, custom, source="custom.json"):
    types = [EntityType(**t) for t in data["entity_types"]]
    by_id = {t.id: t.name for t in types}
    relations = [
        Relation(
            name=r["name"],
            inverse=r["inverse"],
            pairs=frozenset((by_id[s], by_id[t]) for s, t in r["pairs"]),
            generic_target=by_id.get(r.get("generic_target")),
            description=r.get("description", ""),
        )
        for r in data["relations"]
    ]
    custom_names = set()
    type_names = {t.name.lower() for t in types}
    for type_id, t in enumerate(custom.get("entity_types", []), CUSTOM_ID_START):
        if t["name"].lower() in type_names:
            raise CustomFileError(f"{source}: entity type {t['name']} already exists; fix or delete it")
        type_names.add(t["name"].lower())
        types.append(EntityType(id=type_id, name=t["name"], label=t["label"], group=CUSTOM_GROUP,
                                description=t["description"]))
        custom_names.add(t["name"])
    known = {t.name for t in types}
    taken = {n for r in relations for n in (r.name, r.inverse)}
    for r in custom.get("relations", []):
        clash = sorted({r["name"], r["inverse"]} & taken)
        if clash:
            raise CustomFileError(f"{source}: relation name {', '.join(clash)} already used; fix or delete it")
        taken |= {r["name"], r["inverse"]}
        pairs = frozenset((s, t) for s, t in r["pairs"] if s in known and t in known)
        if pairs:  # a relation whose types were all removed is skipped
            relations.append(Relation(name=r["name"], inverse=r["inverse"], pairs=pairs,
                                      description=r.get("description", "")))
            custom_names.update({r["name"], r["inverse"]})
    presets = dict(data.get("presets", {}))
    presets["Everything"] = [t.name for t in types]
    return Schema(types, relations, data.get("assumptions", []), presets, frozenset(custom_names))


@lru_cache(maxsize=None)
def load_base_schema():
    """The PDF schema only, without custom items."""
    return _build(read_json(SCHEMA_PATH), {})


@lru_cache(maxsize=None)
def _load_merged(custom_path):
    path = Path(custom_path)
    custom = check_custom(read_json(path), path.name) if path.exists() else {}
    return _build(read_json(SCHEMA_PATH), custom, path.name)


def load_schema():
    """The PDF schema merged with the custom overlay at CUSTOM_PATH."""
    return _load_merged(CUSTOM_PATH)


def reload_schema():
    """Forget the cached merged schema (call after writing custom.json)."""
    _load_merged.cache_clear()

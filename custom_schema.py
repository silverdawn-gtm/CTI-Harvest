"""Add and delete custom entity types and relations (the schema/custom.json overlay).

The add/delete functions are pure: they take the current custom dict and the merged
schema (for uniqueness checks) and return a new dict. save_custom writes atomically.
"""
import json
import os
import re
import tempfile
from pathlib import Path

from ontology import RELATION_NAME, TYPE_NAME, check_custom, read_json

MAX_PAIRS = 50
MAX_ITEMS = 50          # per list: every custom type goes into the default prompt
CONTROL = re.compile("[\x00-\x1f\x7f]")  # line breaks could forge prompt lines


class CustomSchemaError(ValueError):
    """Invalid custom item (HTTP 422)."""


class NotFound(CustomSchemaError):
    """No such custom item (HTTP 404)."""


class InUse(CustomSchemaError):
    """The item is still referenced (HTTP 409)."""


def _empty():
    return {"entity_types": [], "relations": []}


def load_custom(path):
    path = Path(path)
    if not path.exists():
        return _empty()
    return check_custom(read_json(path), path.name)


def save_custom(path, custom):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".custom-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(custom, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _text(item, key, low, high):
    value = str(item.get(key) or "").strip()
    if not low <= len(value) <= high:
        raise CustomSchemaError(f"{key} must be {low}-{high} characters")
    if CONTROL.search(value):
        raise CustomSchemaError(f"{key} must not contain line breaks or control characters")
    return value


def _check_room(items, what):
    if len(items) >= MAX_ITEMS:
        raise CustomSchemaError(f"at most {MAX_ITEMS} custom {what}; delete one first")


def add_entity_type(custom, schema, item):
    _check_room(custom["entity_types"], "entity types")
    name = str(item.get("name") or "").strip()
    if not TYPE_NAME.fullmatch(name):
        raise CustomSchemaError("name must be one word starting with a capital letter, using letters and "
                                "digits only, 2-40 characters (e.g. CryptoWallet)")
    if name.lower() in {t.name.lower() for t in schema.entity_types}:
        raise CustomSchemaError(f"entity type {name} already exists")
    entry = {"name": name, "label": _text(item, "label", 1, 40), "description": _text(item, "description", 5, 300)}
    return {**custom, "entity_types": [*custom["entity_types"], entry]}


def add_relation(custom, schema, item):
    _check_room(custom["relations"], "relations")
    name = str(item.get("name") or "").strip()
    inverse = str(item.get("inverse") or "").strip() or name
    for field, value in (("name", name), ("inverse", inverse)):
        if not RELATION_NAME.fullmatch(value):
            raise CustomSchemaError(f"{field} must be lowercase letters, digits and hyphens, starting with a "
                                    f"letter, 2-40 characters (e.g. pays-to)")
    taken = {n for r in schema.relations for n in (r.name, r.inverse)}
    clash = sorted({name, inverse} & taken)
    if clash:
        raise CustomSchemaError(f"relation name already used: {', '.join(clash)}")
    description = _text(item, "description", 5, 300)

    types = {t.name for t in schema.entity_types}
    raw_pairs = item.get("pairs")
    if not isinstance(raw_pairs, list):
        raise CustomSchemaError("pairs must be a list of [source, target] pairs")
    pairs = []
    for pair in raw_pairs:
        if not (isinstance(pair, (list, tuple)) and len(pair) == 2):
            raise CustomSchemaError("each pair must be [source, target]")
        source, target = str(pair[0]), str(pair[1])
        unknown = [t for t in (source, target) if t not in types]
        if unknown:
            raise CustomSchemaError(f"unknown entity type in pair: {', '.join(unknown)}")
        if [source, target] not in pairs:
            pairs.append([source, target])
    if not 1 <= len(pairs) <= MAX_PAIRS:
        raise CustomSchemaError(f"give 1-{MAX_PAIRS} pairs")
    entry = {"name": name, "inverse": inverse, "description": description, "pairs": pairs}
    return {**custom, "relations": [*custom["relations"], entry]}


def delete_entity_type(custom, name):
    if name not in {t["name"] for t in custom["entity_types"]}:
        raise NotFound(f"no custom entity type named {name}")
    users = [r["name"] for r in custom["relations"] if any(name in pair for pair in r["pairs"])]
    if users:
        raise InUse(f"{name} is used by custom relation(s) {', '.join(users)}; delete those first")
    return {**custom, "entity_types": [t for t in custom["entity_types"] if t["name"] != name]}


def delete_relation(custom, name):
    if name not in {r["name"] for r in custom["relations"]}:
        raise NotFound(f"no custom relation named {name}")
    return {**custom, "relations": [r for r in custom["relations"] if r["name"] != name]}

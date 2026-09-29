# Custom Entity and Relation Types Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users add and delete their own entity types and relations from the web page. They are saved in `schema/custom.json` and applied everywhere the PDF schema applies.

**Architecture:** `schema/custom.json` is an overlay that `ontology.load_schema()` merges over `schema/schema.json`. The prompt, validator, `relations_for()` and API already read `load_schema()` on each call, so they pick up custom items with no changes. A new `custom_schema.py` holds the add, delete and validation logic as pure functions plus an atomic save. `app.py` exposes it over REST, and `static/index.html` adds the forms.

**Tech Stack:** Python 3.11, FastAPI, pytest, and vanilla JS/HTML with no build step.

**Spec:** `docs/superpowers/specs/2026-09-29-custom-types-design.md`

## Global Constraints

- The PDF schema file `schema/schema.json` is never written by this feature.
- Custom file: `schema/custom.json`, shape `{"entity_types": [...], "relations": [...]}`. A missing file means no custom items.
- Entity type name: `^[A-Z][A-Za-z0-9]{1,39}$`, unique case-insensitively across all entity types (built-in and custom).
- Entity label: 1–40 characters. Descriptions: 5–300 characters. All text is trimmed first.
- Relation name and inverse: `^[a-z][a-z0-9-]{1,39}$`. The inverse defaults to the name (symmetric). Neither may equal any existing relation name or inverse.
- Relation pairs: 1–50 `[source, target]` pairs of existing types, with duplicates removed.
- Custom entity types get IDs 101, 102, … in file order and `group = "Custom"`.
- The "Everything" preset lists every entity type, custom included.
- Deleting an entity type used by a custom relation is refused (409). Deleting an unknown name returns 404. Validation errors return 422.
- Writes are atomic: write a temporary file in the same directory, then `os.replace`.
- No test may read or write the real `schema/custom.json`.
- This project is not a git repository. Where the template says "commit", run the full suite instead: `python -m pytest -q -p no:cacheprovider`.

## Review Focus

1. **The real `schema/custom.json` leaking into tests.** A user who adds custom types must not break the test suite. Pinned in Task 1 by an autouse fixture plus a test that proves the patched path is used.
2. **A hand-edited or corrupt `custom.json`.** Invalid JSON should give a clear error naming the file, not a bare 500. Pinned in Task 1 (the loader error) and Task 3 (the API returns the message).
3. **Case and whitespace in names.** `" CryptoWallet "` should be accepted after trimming, and `"MALWARE"` rejected as a clash with `Malware`. Pinned in Task 2.
4. **A relation name that equals an existing *inverse* name** (e.g. `used-by`). It should be rejected like a clash with a forward name. Pinned in Task 2.
5. **A type deleted while a browser still has it selected.** An extraction that sends the deleted type should get a clear 422, not a crash, and the page should drop unknown types when restoring its saved selection. Pinned in Task 3 (API) and Task 4 (page).

---

## File Structure

| File | Responsibility |
|---|---|
| `ontology.py` (modify) | Merges the overlay: `CUSTOM_PATH`, `load_base_schema()`, `reload_schema()`, `Schema.is_custom()`, `CustomFileError`, computed "Everything" preset |
| `custom_schema.py` (create) | Pure add/delete/validate functions over the custom dict, `load_custom()`, atomic `save_custom()`, error classes |
| `app.py` (modify) | `/custom` endpoints, custom flags in `/schema`, `CustomFileError` handler |
| `static/index.html` (modify) | Custom group with delete buttons, "Custom types" panel with the two forms |
| `tests/conftest.py` (create) | Autouse fixture pointing `ontology.CUSTOM_PATH` at a temporary file |
| `tests/test_ontology.py`, `tests/test_llm.py` (modify) | PDF-fidelity tests use `load_base_schema()`; new merge tests |
| `tests/test_custom_schema.py` (create) | Validation rules and save/load |
| `tests/test_validator.py`, `tests/test_app.py` (modify) | Custom relation through the validator; API endpoints |

---

### Task 1: Merge the custom overlay in `ontology.py`

**Files:**
- Create: `tests/conftest.py`
- Modify: `ontology.py` (the module's constants, the `Schema` dataclass, and `load_schema` at the end of the file)
- Modify: `tests/test_ontology.py` (the `schema` fixture near the top, and new tests at the end)
- Modify: `tests/test_llm.py` (the `EVERYTHING` constant)
- Modify: `tests/test_validator.py` (new test at the end)

**Interfaces:**
- Consumes: the existing `Schema`, `EntityType`, `Relation` and `SCHEMA_PATH` in `ontology.py`.
- Produces:
  - `ontology.CUSTOM_PATH: Path`
  - `ontology.CustomFileError(ValueError)`
  - `ontology.read_json(path) -> dict`, which raises `CustomFileError` on invalid JSON
  - `ontology.load_base_schema() -> Schema`
  - `ontology.load_schema() -> Schema` (merged)
  - `ontology.reload_schema() -> None`
  - `Schema.is_custom(name: str) -> bool`
  - `tests/conftest.py` fixture `isolated_custom_schema -> Path` (the temporary `custom.json` path, which doesn't exist yet)

- [ ] **Step 1: Add the isolation fixture**

Create `tests/conftest.py`:

```python
import pytest

import ontology


@pytest.fixture(autouse=True)
def isolated_custom_schema(tmp_path, monkeypatch):
    """Point the custom schema overlay at a temporary file; tests never touch schema/custom.json."""
    path = tmp_path / "custom.json"
    monkeypatch.setattr(ontology, "CUSTOM_PATH", path)
    ontology.reload_schema()
    yield path
    ontology.reload_schema()
```

- [ ] **Step 2: Make the PDF-fidelity tests use the base schema**

In `tests/test_ontology.py`, change the import and the module-scoped fixture. It is created before the autouse fixture runs, so it must not read the overlay.

```python
from ontology import load_base_schema, load_schema, reload_schema
```

```python
@pytest.fixture(scope="module")
def schema():
    return load_base_schema()
```

In `tests/test_llm.py`, change the imports and `EVERYTHING`. The constant is evaluated at import time, before fixtures run.

```python
from ontology import load_base_schema, load_schema
```

```python
EVERYTHING = set(load_base_schema().presets["Everything"])
```

- [ ] **Step 3: Write the failing merge tests**

Append to `tests/test_ontology.py`:

```python
# --- custom overlay (schema/custom.json) -------------------------------------------------
import json

CUSTOM = {
    "entity_types": [{"name": "CryptoWallet", "label": "Crypto wallet",
                      "description": "A cryptocurrency wallet or address."}],
    "relations": [{"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
                   "pairs": [["ThreatGroup", "CryptoWallet"]]}],
}


def write_custom(path, data):
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    reload_schema()


def test_tests_use_a_temporary_custom_file(isolated_custom_schema):
    import ontology
    assert ontology.CUSTOM_PATH == isolated_custom_schema
    assert isolated_custom_schema != ontology.SCHEMA_DIR / "custom.json"


def test_without_a_custom_file_the_schema_is_the_base():
    assert [t.name for t in load_schema().entity_types] == [t.name for t in load_base_schema().entity_types]


def test_custom_entity_type_is_merged_into_a_custom_group(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    t = load_schema().entity_types[-1]
    assert (t.id, t.name, t.label, t.group) == (101, "CryptoWallet", "Crypto wallet", "Custom")
    assert load_schema().is_custom("CryptoWallet") and load_schema().is_custom("pays-to")
    assert not load_schema().is_custom("Malware")


def test_custom_relation_works_like_a_built_in_one(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    s = load_schema()
    assert s.allowed("ThreatGroup", "pays-to", "CryptoWallet")
    assert s.allowed("CryptoWallet", "paid-by", "ThreatGroup")
    assert not s.allowed("Malware", "pays-to", "CryptoWallet")
    assert s.inverse("pays-to") == "paid-by"
    assert s.relations_for({"ThreatGroup", "CryptoWallet"})["pays-to"] == [("ThreatGroup", "CryptoWallet")]


def test_everything_preset_includes_custom_types(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    assert load_schema().presets["Everything"][-1] == "CryptoWallet"
    assert len(load_schema().presets["Everything"]) == 16


def test_custom_items_never_reach_the_base_schema(isolated_custom_schema):
    write_custom(isolated_custom_schema, CUSTOM)
    assert "CryptoWallet" not in {t.name for t in load_base_schema().entity_types}


def test_custom_pairs_with_unknown_types_are_skipped(isolated_custom_schema):
    data = {"entity_types": [], "relations": [
        {"name": "haunts", "inverse": "haunted-by", "description": "ghost story",
         "pairs": [["ThreatGroup", "Ghost"]]}]}
    write_custom(isolated_custom_schema, data)
    assert "haunts" not in {r.name for r in load_schema().relations}


def test_invalid_custom_json_gives_a_clear_error(isolated_custom_schema):
    from ontology import CustomFileError
    write_custom(isolated_custom_schema, "{oops")
    with pytest.raises(CustomFileError, match="custom.json is not valid JSON"):
        load_schema()
```

Append to `tests/test_validator.py`:

```python
def test_custom_relation_survives_validation(isolated_custom_schema):
    import json
    from ontology import reload_schema
    isolated_custom_schema.write_text(json.dumps({
        "entity_types": [{"name": "CryptoWallet", "label": "Crypto wallet", "description": "A wallet."}],
        "relations": [{"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
                       "pairs": [["ThreatGroup", "CryptoWallet"]]}]}), encoding="utf-8")
    reload_schema()
    spans = [[0, 1, "Lazarus", "ThreatGroup"], [4, 5, "4AdUndX", "CryptoWallet"]]
    kept, triples, dropped = validate(spans, [(1, "paid-by", 0)], {"ThreatGroup", "CryptoWallet"})
    assert triples == [(0, "pays-to", 1)] and dropped == []
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/test_ontology.py tests/test_validator.py tests/test_llm.py`
Expected: an ImportError or collection error mentioning `load_base_schema` or `reload_schema`.

- [ ] **Step 5: Implement the overlay in `ontology.py`**

Replace the module docstring and constants with:

```python
"""Load the entity/relation schema: schema/schema.json (from the PDF) merged with the
user's custom overlay schema/custom.json.

Type arguments are BIO names ("ThreatGroup"); relation arguments may be a stored
name ("uses") or its inverse ("used-by").
"""
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
SCHEMA_PATH = SCHEMA_DIR / "schema.json"
CUSTOM_PATH = SCHEMA_DIR / "custom.json"   # read at call time, so tests can point it elsewhere
CUSTOM_GROUP = "Custom"
CUSTOM_ID_START = 101


class CustomFileError(ValueError):
    """A schema file could not be read."""
```

Add a field and a method to `Schema`: put the field after `presets`, and the method after `type_name`.

```python
    custom_names: frozenset = frozenset()   # custom entity types and relation names
```

```python
    def is_custom(self, name):
        return name in self.custom_names
```

Replace `load_schema` (the last function in the file) with:

```python
def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise CustomFileError(f"{Path(path).name} is not valid JSON ({err}); fix or delete {path}") from err


def _build(data, custom):
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
    for type_id, t in enumerate(custom.get("entity_types", []), CUSTOM_ID_START):
        types.append(EntityType(id=type_id, name=t["name"], label=t["label"], group=CUSTOM_GROUP,
                                description=t["description"]))
        custom_names.add(t["name"])
    known = {t.name for t in types}
    for r in custom.get("relations", []):
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
    custom = read_json(custom_path) if Path(custom_path).exists() else {}
    return _build(read_json(SCHEMA_PATH), custom)


def load_schema():
    """The PDF schema merged with the custom overlay at CUSTOM_PATH."""
    return _load_merged(CUSTOM_PATH)


def reload_schema():
    """Forget the cached merged schema (call after writing custom.json)."""
    _load_merged.cache_clear()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest -q -p no:cacheprovider tests/test_ontology.py tests/test_validator.py tests/test_llm.py`
Expected: all pass.

- [ ] **Step 7: Full suite (in place of a commit)**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: all pass.

---

### Task 2: `custom_schema.py`: add, delete, validate and save

**Files:**
- Create: `custom_schema.py`
- Create: `tests/test_custom_schema.py`

**Interfaces:**
- Consumes (from Task 1):
  - `ontology.read_json(path)` and `ontology.CustomFileError`
  - `ontology.load_schema()` / `ontology.load_base_schema()` / `ontology.reload_schema()`
  - the `isolated_custom_schema` fixture
- Produces:
  - `CustomSchemaError(ValueError)` (→ 422), `NotFound(CustomSchemaError)` (→ 404), `InUse(CustomSchemaError)` (→ 409)
  - `load_custom(path) -> dict`, `save_custom(path, custom) -> None`
  - `add_entity_type(custom, schema, item: dict) -> dict`, `add_relation(custom, schema, item: dict) -> dict`
  - `delete_entity_type(custom, name) -> dict`, `delete_relation(custom, name) -> dict`

  All the add and delete functions return a new dict and never mutate their input.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_custom_schema.py`:

```python
import json

import pytest

from custom_schema import (CustomSchemaError, InUse, NotFound, add_entity_type, add_relation,
                           delete_entity_type, delete_relation, load_custom, save_custom)
from ontology import load_base_schema, load_schema, reload_schema

EMPTY = {"entity_types": [], "relations": []}
WALLET = {"name": "CryptoWallet", "label": "Crypto wallet", "description": "A cryptocurrency wallet."}
PAYS = {"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
        "pairs": [["ThreatGroup", "CryptoWallet"]]}


def with_wallet(path):
    """Save a custom file containing CryptoWallet and return the merged schema."""
    save_custom(path, add_entity_type(EMPTY, load_base_schema(), WALLET))
    reload_schema()
    return load_schema()


# --- entity types -------------------------------------------------------------------------

def test_add_entity_type():
    out = add_entity_type(EMPTY, load_base_schema(), WALLET)
    assert out["entity_types"] == [WALLET]
    assert EMPTY["entity_types"] == []  # input not mutated


def test_add_entity_type_trims_whitespace():
    out = add_entity_type(EMPTY, load_base_schema(),
                          {"name": " CryptoWallet ", "label": " Crypto wallet ", "description": "  A wallet.  "})
    assert out["entity_types"] == [{"name": "CryptoWallet", "label": "Crypto wallet", "description": "A wallet."}]


@pytest.mark.parametrize("name", ["cryptoWallet", "Crypto Wallet", "Crypto-Wallet", "C", "X" * 41, ""])
def test_entity_type_name_must_be_one_capitalised_word(name):
    with pytest.raises(CustomSchemaError, match="one word"):
        add_entity_type(EMPTY, load_base_schema(), {**WALLET, "name": name})


@pytest.mark.parametrize("name", ["Malware", "MALWARE", "Threatgroup"])
def test_entity_type_name_must_not_clash_with_a_built_in(name):
    with pytest.raises(CustomSchemaError, match="already exists"):
        add_entity_type(EMPTY, load_base_schema(), {**WALLET, "name": name})


def test_entity_type_name_must_not_clash_with_a_custom_type(isolated_custom_schema):
    schema = with_wallet(isolated_custom_schema)
    with pytest.raises(CustomSchemaError, match="already exists"):
        add_entity_type(load_custom(isolated_custom_schema), schema, WALLET)


@pytest.mark.parametrize("field,value", [("label", ""), ("label", "x" * 41),
                                         ("description", "abc"), ("description", "x" * 301)])
def test_entity_type_text_lengths(field, value):
    with pytest.raises(CustomSchemaError, match=field):
        add_entity_type(EMPTY, load_base_schema(), {**WALLET, field: value})


# --- relations ----------------------------------------------------------------------------

def test_add_relation(isolated_custom_schema):
    schema = with_wallet(isolated_custom_schema)
    out = add_relation(load_custom(isolated_custom_schema), schema, PAYS)
    assert out["relations"] == [PAYS]


def test_relation_inverse_defaults_to_the_name_for_symmetric_relations(isolated_custom_schema):
    schema = with_wallet(isolated_custom_schema)
    out = add_relation(load_custom(isolated_custom_schema), schema,
                       {"name": "shares-wallet", "inverse": "", "description": "two groups share a wallet",
                        "pairs": [["ThreatGroup", "ThreatGroup"]]})
    assert out["relations"][0]["inverse"] == "shares-wallet"


def test_relation_pairs_may_use_only_built_in_types():
    out = add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": [["ThreatGroup", "Organization"]]})
    assert out["relations"][0]["pairs"] == [["ThreatGroup", "Organization"]]


@pytest.mark.parametrize("name", ["Pays-to", "pays to", "pays_to", "-pays", "p"])
def test_relation_name_format(name):
    with pytest.raises(CustomSchemaError, match="lowercase"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "name": name, "pairs": [["ThreatGroup", "Malware"]]})


@pytest.mark.parametrize("name,inverse", [("uses", "used-with"), ("used-by", "uses-x"),
                                          ("deploys", "alias-of")])
def test_relation_names_must_not_clash_with_existing_names_or_inverses(name, inverse):
    with pytest.raises(CustomSchemaError, match="already used"):
        add_relation(EMPTY, load_base_schema(),
                     {**PAYS, "name": name, "inverse": inverse, "pairs": [["ThreatGroup", "Malware"]]})


def test_relation_pairs_must_use_known_types():
    with pytest.raises(CustomSchemaError, match="unknown entity type in pair: Ghost"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": [["ThreatGroup", "Ghost"]]})


@pytest.mark.parametrize("pairs", [[], [["ThreatGroup"]], [["ThreatGroup", "Malware", "Tool"]], "ThreatGroup"])
def test_relation_pairs_shape(pairs):
    with pytest.raises(CustomSchemaError, match="pair"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": pairs})


def test_relation_pairs_are_deduplicated():
    out = add_relation(EMPTY, load_base_schema(),
                       {**PAYS, "pairs": [["ThreatGroup", "Malware"], ["ThreatGroup", "Malware"]]})
    assert out["relations"][0]["pairs"] == [["ThreatGroup", "Malware"]]


def test_relation_pairs_limit():
    pairs = [[a.name, b.name] for a in load_base_schema().entity_types for b in load_base_schema().entity_types][:51]
    with pytest.raises(CustomSchemaError, match="1-50 pairs"):
        add_relation(EMPTY, load_base_schema(), {**PAYS, "pairs": pairs})


# --- deletes ------------------------------------------------------------------------------

def test_delete_entity_type():
    custom = {"entity_types": [WALLET], "relations": []}
    assert delete_entity_type(custom, "CryptoWallet") == EMPTY


def test_delete_entity_type_in_use_is_refused():
    custom = {"entity_types": [WALLET], "relations": [PAYS]}
    with pytest.raises(InUse, match="pays-to"):
        delete_entity_type(custom, "CryptoWallet")


def test_delete_built_in_or_unknown_type_is_not_found():
    with pytest.raises(NotFound):
        delete_entity_type(EMPTY, "Malware")


def test_delete_relation():
    custom = {"entity_types": [WALLET], "relations": [PAYS]}
    assert delete_relation(custom, "pays-to") == {"entity_types": [WALLET], "relations": []}
    with pytest.raises(NotFound):
        delete_relation(custom, "uses")


# --- load / save --------------------------------------------------------------------------

def test_load_missing_file_is_empty(tmp_path):
    assert load_custom(tmp_path / "nope.json") == EMPTY


def test_save_then_load_round_trips_and_leaves_no_temp_files(tmp_path):
    path = tmp_path / "custom.json"
    custom = {"entity_types": [WALLET], "relations": [PAYS]}
    save_custom(path, custom)
    assert load_custom(path) == custom
    assert [p.name for p in tmp_path.iterdir()] == ["custom.json"]


def test_load_invalid_file_raises_a_clear_error(tmp_path):
    from ontology import CustomFileError
    path = tmp_path / "custom.json"
    path.write_text("{oops", encoding="utf-8")
    with pytest.raises(CustomFileError, match="not valid JSON"):
        load_custom(path)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/test_custom_schema.py`
Expected: an ImportError, `No module named 'custom_schema'`.

- [ ] **Step 3: Implement `custom_schema.py`**

```python
"""Add and delete custom entity types and relations (the schema/custom.json overlay).

The add/delete functions are pure: they take the current custom dict and the merged
schema (for uniqueness checks) and return a new dict. save_custom writes atomically.
"""
import json
import os
import re
import tempfile
from pathlib import Path

from ontology import read_json

TYPE_NAME = re.compile(r"[A-Z][A-Za-z0-9]{1,39}")
RELATION_NAME = re.compile(r"[a-z][a-z0-9-]{1,39}")
MAX_PAIRS = 50


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
    data = read_json(path)
    return {"entity_types": list(data.get("entity_types", [])), "relations": list(data.get("relations", []))}


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
    return value


def add_entity_type(custom, schema, item):
    name = str(item.get("name") or "").strip()
    if not TYPE_NAME.fullmatch(name):
        raise CustomSchemaError("name must be one word starting with a capital letter, using letters and "
                                "digits only, 2-40 characters (e.g. CryptoWallet)")
    if name.lower() in {t.name.lower() for t in schema.entity_types}:
        raise CustomSchemaError(f"entity type {name} already exists")
    entry = {"name": name, "label": _text(item, "label", 1, 40), "description": _text(item, "description", 5, 300)}
    return {**custom, "entity_types": [*custom["entity_types"], entry]}


def add_relation(custom, schema, item):
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest -q -p no:cacheprovider tests/test_custom_schema.py`
Expected: all pass.

- [ ] **Step 5: Full suite (in place of a commit)**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: all pass.

---

### Task 3: API endpoints in `app.py`

**Files:**
- Modify: `app.py` (imports, the `/schema` handler, and new handlers at the end)
- Modify: `tests/test_app.py` (new tests at the end)

**Interfaces:**
- Consumes:
  - from Task 1: `ontology.CUSTOM_PATH`, `ontology.reload_schema`, `ontology.CustomFileError`, `Schema.is_custom`
  - from Task 2: every function and error class in `custom_schema`
- Produces the HTTP API:
  - `GET /custom`
  - `POST /custom/entity-types` with `{name, label, description}` → 201
  - `DELETE /custom/entity-types/{name}` → 200, 404 or 409
  - `POST /custom/relations` with `{name, inverse?, description, pairs}` → 201 or 422
  - `DELETE /custom/relations/{name}` → 200 or 404
  - `GET /schema` gains `entity_types[].custom: bool` and `relations: [{name, inverse, description, custom}]`

  Every successful write returns the full custom dict.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_app.py`:

```python
# --- custom types -------------------------------------------------------------------------

WALLET = {"name": "CryptoWallet", "label": "Crypto wallet", "description": "A cryptocurrency wallet or address."}
PAYS = {"name": "pays-to", "inverse": "paid-by", "description": "pays to a wallet",
        "pairs": [["ThreatGroup", "CryptoWallet"]]}


def test_add_custom_entity_type(client):
    response = client.post("/custom/entity-types", json=WALLET)
    assert response.status_code == 201
    assert response.json()["entity_types"] == [WALLET]
    types = {t["name"]: t for t in client.get("/schema").json()["entity_types"]}
    assert types["CryptoWallet"]["custom"] is True and types["CryptoWallet"]["group"] == "Custom"
    assert types["Malware"]["custom"] is False
    assert client.get("/custom").json()["entity_types"] == [WALLET]


def test_invalid_custom_entity_type_is_422_with_a_message(client):
    response = client.post("/custom/entity-types", json={**WALLET, "name": "crypto wallet"})
    assert response.status_code == 422 and "one word" in response.json()["detail"]


def test_add_custom_relation_shows_in_relations(client):
    client.post("/custom/entity-types", json=WALLET)
    assert client.post("/custom/relations", json=PAYS).status_code == 201
    rels = client.get("/relations", params={"types": "ThreatGroup,CryptoWallet"}).json()
    assert rels["pays-to"]["pairs"] == [["ThreatGroup", "CryptoWallet"]]
    listed = {r["name"]: r for r in client.get("/schema").json()["relations"]}
    assert listed["pays-to"]["custom"] is True and listed["uses"]["custom"] is False


def test_delete_type_in_use_is_409_then_works_after_the_relation_is_gone(client):
    client.post("/custom/entity-types", json=WALLET)
    client.post("/custom/relations", json=PAYS)
    response = client.delete("/custom/entity-types/CryptoWallet")
    assert response.status_code == 409 and "pays-to" in response.json()["detail"]
    assert client.delete("/custom/relations/pays-to").status_code == 200
    assert client.delete("/custom/entity-types/CryptoWallet").json() == {"entity_types": [], "relations": []}


def test_delete_unknown_or_built_in_is_404(client):
    assert client.delete("/custom/entity-types/Malware").status_code == 404
    assert client.delete("/custom/relations/uses").status_code == 404


def test_extract_with_a_deleted_type_is_422(client):
    client.post("/custom/entity-types", json=WALLET)
    client.delete("/custom/entity-types/CryptoWallet")
    assert extract(client, text="x", entity_types=["CryptoWallet"]).status_code == 422


def test_extract_finds_custom_types_and_relations():
    class WalletLLM:
        def extract(self, sentence, entity_types, relation_types=None, known=()):
            return [("4AdUndX", "CryptoWallet")], [("APT28", "pays-to", "4AdUndX")]

    c = client_with(WalletLLM())
    try:
        c.post("/custom/entity-types", json=WALLET)
        c.post("/custom/relations", json=PAYS)
        rec = extract(c, text="APT28 paid 4AdUndX.", entity_types=["ThreatGroup", "CryptoWallet"]).json()["records"][0]
    finally:
        app.dependency_overrides.clear()
    assert [(e[2], e[3]) for e in rec["entities"]] == [("APT28", "ThreatGroup"), ("4AdUndX", "CryptoWallet")]
    assert rec["relations"] == [["pays-to", 1, 0]]


def test_corrupt_custom_file_gives_a_readable_error(client, isolated_custom_schema):
    isolated_custom_schema.write_text("{oops", encoding="utf-8")
    from ontology import reload_schema
    reload_schema()
    response = client.get("/schema")
    assert response.status_code == 500 and "not valid JSON" in response.json()["detail"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/test_app.py`
Expected: the new tests fail with 404/405 for the missing routes, and `KeyError: 'custom'`.

- [ ] **Step 3: Implement**

In `app.py`, extend the imports:

```python
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse

import ontology
from custom_schema import (CustomSchemaError, InUse, NotFound, add_entity_type, add_relation,
                           delete_entity_type, delete_relation, load_custom, save_custom)
```

Add the request models after `ExtractRequest`:

```python
class EntityTypeIn(BaseModel):
    name: str
    label: str
    description: str


class RelationIn(BaseModel):
    name: str
    inverse: str = ""          # empty: symmetric (same as name)
    description: str
    pairs: list[list[str]]
```

Add the error handler after `app = FastAPI(...)`:

```python
@app.exception_handler(ontology.CustomFileError)
def custom_file_error(request: Request, err: ontology.CustomFileError):
    return JSONResponse(status_code=500, content={"detail": str(err)})
```

Replace the `/schema` handler with:

```python
@app.get("/schema")
def schema():
    s = load_schema()
    return {
        "entity_types": [{"name": t.name, "label": t.label, "group": t.group, "description": t.description,
                          "custom": s.is_custom(t.name)} for t in s.entity_types],
        "relations": [{"name": r.name, "inverse": r.inverse, "description": r.description,
                       "custom": s.is_custom(r.name)} for r in s.relations],
        "presets": s.presets,
    }
```

Add at the end of `app.py`:

```python
def _change(change):
    """Apply a change to schema/custom.json, save it, and reload the schema."""
    path = ontology.CUSTOM_PATH
    try:
        custom = change(load_custom(path))
    except NotFound as err:
        raise HTTPException(status_code=404, detail=str(err))
    except InUse as err:
        raise HTTPException(status_code=409, detail=str(err))
    except CustomSchemaError as err:
        raise HTTPException(status_code=422, detail=str(err))
    save_custom(path, custom)
    ontology.reload_schema()
    return custom


@app.get("/custom")
def get_custom():
    return load_custom(ontology.CUSTOM_PATH)


@app.post("/custom/entity-types", status_code=201)
def post_custom_entity_type(item: EntityTypeIn):
    return _change(lambda custom: add_entity_type(custom, load_schema(), item.model_dump()))


@app.delete("/custom/entity-types/{name}")
def delete_custom_entity_type(name: str):
    return _change(lambda custom: delete_entity_type(custom, name))


@app.post("/custom/relations", status_code=201)
def post_custom_relation(item: RelationIn):
    return _change(lambda custom: add_relation(custom, load_schema(), item.model_dump()))


@app.delete("/custom/relations/{name}")
def delete_custom_relation(name: str):
    return _change(lambda custom: delete_relation(custom, name))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest -q -p no:cacheprovider tests/test_app.py`
Expected: all pass.

- [ ] **Step 5: Full suite (in place of a commit)**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: all pass.

---

### Task 4: Page (`static/index.html`)

**Files:**
- Modify: `static/index.html`
- Test: `tests/test_app.py` (a page-content check). The browser behaviour itself is checked by hand in Task 5.

**Interfaces:**
- Consumes (from Task 3): `GET /schema` (with `custom` flags and `relations`), `POST/DELETE /custom/entity-types`, `POST/DELETE /custom/relations`, and the existing `GET /relations`.
- Produces: the UI only.

- [ ] **Step 1: Write the failing page test**

Append to `tests/test_app.py`:

```python
def test_page_has_the_custom_types_panel(client):
    html = client.get("/").text
    assert 'id="custom-panel"' in html and "/custom/entity-types" in html and "/custom/relations" in html
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest -q -p no:cacheprovider tests/test_app.py::test_page_has_the_custom_types_panel`
Expected: FAIL.

- [ ] **Step 3: Add the CSS**

Insert before `[hidden] { display: none !important; }`:

```css
  button.x { background: none; border: none; color: var(--muted); padding: 0 4px; font-size: 14px; line-height: 1; }
  button.x:hover { color: var(--err); }
  button.x.armed { color: var(--err); font-size: 12px; }
  details.panel summary { cursor: pointer; font-weight: 600; font-size: 14px; }
  .custom-forms { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 10px; }
  .custom-forms h3 { font-size: 13px; margin: 0 0 6px; }
  .field { display: flex; flex-direction: column; gap: 2px; margin-bottom: 6px; font-size: 13px; color: var(--muted); }
  .field input, .field select { font: inherit; font-size: 14px; color: var(--fg); background: var(--bg);
                                border: 1px solid var(--line); border-radius: 6px; padding: 5px 8px; min-width: 0; }
  .pair-row { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  .pair-row select { flex: 1 1 120px; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px 10px; margin: 6px 0; font-size: 13px; }
  .chips span { font-family: ui-monospace, Consolas, monospace; }
  .form-error { color: var(--err); font-size: 13px; min-height: 1em; }
```

- [ ] **Step 4: Add the panel HTML**

Insert right after the closing `</div>` of `<div class="panels">` (before `<div class="bar">` that holds the Extract button):

```html
  <details class="panel" id="custom-panel" style="margin-top: 10px">
    <summary>Custom types</summary>
    <div class="custom-forms">
      <form id="type-form">
        <h3>Add entity type</h3>
        <label class="field">Name (one word, e.g. CryptoWallet)<input name="name" required></label>
        <label class="field">Label<input name="label" required></label>
        <label class="field">Description (used by the LLM)<input name="description" required></label>
        <button type="submit" class="small">Add entity type</button>
        <div class="form-error" id="type-error"></div>
      </form>
      <form id="rel-form">
        <h3>Add relation</h3>
        <label class="field">Name (e.g. pays-to)<input name="name" required></label>
        <label class="field">Inverse (e.g. paid-by; empty = same)<input name="inverse"></label>
        <label class="field">Description<input name="description" required></label>
        <div class="field">Allowed pairs (source → target)
          <div class="pair-row">
            <select id="pair-source"></select><span>→</span><select id="pair-target"></select>
            <button type="button" class="ghost small" id="pair-add">Add pair</button>
          </div>
        </div>
        <div class="chips" id="pair-list"></div>
        <button type="submit" class="small">Add relation</button>
        <div class="form-error" id="rel-error"></div>
      </form>
    </div>
    <div class="field" style="margin-top: 8px">Custom relations</div>
    <div class="chips" id="custom-rels"></div>
  </details>
```

- [ ] **Step 5: Update the JS**

Add after the `COLORS` constant:

```js
const CUSTOM_COLORS = ["#e9d5ff", "#fed7aa", "#bbf7d0", "#bfdbfe", "#fde68a", "#fbcfe8", "#99f6e4", "#ddd6fe"];
let pendingPairs = [];

function colorOf(name) {
  if (COLORS[name]) return COLORS[name];
  const custom = schema ? schema.entity_types.filter((t) => t.custom).map((t) => t.name) : [];
  return CUSTOM_COLORS[Math.max(0, custom.indexOf(name)) % CUSTOM_COLORS.length];
}
```

Replace every `COLORS[t.name]`, `COLORS[type]` and `COLORS[l]` lookup with `colorOf(...)`. The places are the swatch in `renderTypes`, the mark in `renderSentence` (`colorOf(type)` replaces `COLORS[type] || "#e7e5e4"`), and the legend in `render`.

In `renderTypes`, add a delete button to each custom type's label. Replace the label template with:

```js
      <label class="check" title="${esc(t.description)}">
        <input type="checkbox" data-type="${t.name}" ${selectedTypes.has(t.name) ? "checked" : ""}>
        <span class="swatch" style="background:${colorOf(t.name)}"></span>${esc(t.label)}
        ${t.custom ? `<button type="button" class="x" data-delete-type="${t.name}" title="Delete ${esc(t.label)}">×</button>` : ""}
      </label>`
```

Add these functions before `async function init()`:

```js
function renderCustomPanel() {
  const options = schema.entity_types.map((t) => `<option value="${t.name}">${esc(t.label)}</option>`).join("");
  $("pair-source").innerHTML = options;
  $("pair-target").innerHTML = options;
  $("pair-list").innerHTML = pendingPairs.map(([s, t], k) =>
    `<span>${esc(s)} → ${esc(t)} <button type="button" class="x" data-pair="${k}" title="Remove">×</button></span>`).join("")
    || `<span class="empty">No pairs yet.</span>`;
  const custom = schema.relations.filter((r) => r.custom);
  $("custom-rels").innerHTML = custom.map((r) =>
    `<span title="${esc(r.description)}">${esc(r.name)} / ${esc(r.inverse)}
       <button type="button" class="x" data-delete-rel="${r.name}" title="Delete ${esc(r.name)}">×</button></span>`).join("")
    || `<span class="empty">None yet.</span>`;
}

async function reloadSchema(selectType) {
  schema = await (await fetch("/schema")).json();
  const known = new Set(schema.entity_types.map((t) => t.name));
  selectedTypes = new Set([...selectedTypes].filter((t) => known.has(t)));
  if (selectType) selectedTypes.add(selectType);
  save();
  renderTypes();
  renderCustomPanel();
  refreshRelations();
}

async function send(method, url, body) {
  const res = await fetch(url, {
    method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    throw new Error(detail || res.statusText);
  }
  return data;
}

// Two-click delete inside the page (no browser confirm dialog): first click arms, second deletes.
async function armedDelete(button, url, errorBox) {
  if (!button.classList.contains("armed")) {
    button.classList.add("armed");
    button.textContent = "delete?";
    setTimeout(() => { button.classList.remove("armed"); button.textContent = "×"; }, 3000);
    return;
  }
  try {
    await send("DELETE", url);
    errorBox.textContent = "";
    await reloadSchema();
  } catch (err) {
    errorBox.textContent = err.message;
  }
}
```

In `init()`, add `renderCustomPanel();` after `renderTypes();`.

Change the existing `$("types")` `change` listener to leave the delete buttons alone. It already returns when `dataset.type` is missing, so no change is needed there. Add a `click` listener for the delete buttons, and the form handlers, next to the other listeners:

```js
$("types").addEventListener("click", (e) => {
  const name = e.target.dataset.deleteType;
  if (!name) return;
  e.preventDefault();  // don't toggle the checkbox in the same label
  armedDelete(e.target, `/custom/entity-types/${encodeURIComponent(name)}`, $("type-error"));
});
$("custom-rels").addEventListener("click", (e) => {
  const name = e.target.dataset.deleteRel;
  if (name) armedDelete(e.target, `/custom/relations/${encodeURIComponent(name)}`, $("rel-error"));
});
$("pair-list").addEventListener("click", (e) => {
  if (e.target.dataset.pair === undefined) return;
  pendingPairs.splice(Number(e.target.dataset.pair), 1);
  renderCustomPanel();
});
$("pair-add").addEventListener("click", () => {
  const pair = [$("pair-source").value, $("pair-target").value];
  if (!pendingPairs.some(([s, t]) => s === pair[0] && t === pair[1])) pendingPairs.push(pair);
  renderCustomPanel();
});
$("type-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const item = Object.fromEntries(["name", "label", "description"].map((k) => [k, form.get(k).trim()]));
  try {
    await send("POST", "/custom/entity-types", item);
    e.target.reset();
    $("type-error").textContent = "";
    await reloadSchema(item.name);
  } catch (err) {
    $("type-error").textContent = err.message;
  }
});
$("rel-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const item = { name: form.get("name").trim(), inverse: form.get("inverse").trim(),
                 description: form.get("description").trim(), pairs: pendingPairs };
  try {
    await send("POST", "/custom/relations", item);
    e.target.reset();
    pendingPairs = [];
    $("rel-error").textContent = "";
    await reloadSchema();
  } catch (err) {
    $("rel-error").textContent = err.message;
  }
});
```

- [ ] **Step 6: Run the page test and the full suite**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: all pass, including `test_page_has_the_custom_types_panel`.

---

### Task 5: End-to-end check

**Files:** none (verification only).

- [ ] **Step 1: Live extraction with a custom type, without touching the real custom file**

Run a script that points `ontology.CUSTOM_PATH` at a temporary file. It adds `CryptoWallet` and `pays-to` through `custom_schema`, calls `pipeline.extract_records` with the Mistral extractor on "In 2021, Lazarus Group sent the ransom to the Monero wallet 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge.", and checks that the record is valid and every relation is allowed.
Expected: `CryptoWallet` found, and `Lazarus Group pays-to <wallet>` (or no relation); no invalid output.

- [ ] **Step 2: Manual page check**

Reload http://localhost:8000:
1. Open "Custom types", add `CryptoWallet`, and check it appears (ticked) in a Custom group.
2. Add the relation `pays-to` with pair ThreatGroup → CryptoWallet, and check it appears in the relation panel when both types are ticked.
3. Delete the type: this should be refused with a message naming `pays-to`.
4. Delete the relation, then the type, and check both disappear.

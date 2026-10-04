# Custom Entity and Relation Types: Design

Date: 2026-09-29
Status: approved in conversation, pending spec review

## Goal

Let the user add their own entity types and relations from the web page. They persist in the project, apply everywhere the built-in (PDF) schema applies, and never modify the PDF schema itself.

## Decisions (from the user)

| Question | Decision |
|---|---|
| Where custom items live | Saved in the project, shared by everyone using this server |
| How custom entities are found | By the LLM only (name + description); no keywords or regex |
| What custom relations can do | New relations only, with allowed pairs between any types (built-in or custom); built-in relations are not extended |
| Storage approach | Overlay file `schema/custom.json`, merged over `schema/schema.json` at load time |

## Assumptions (confirmed by approval)

- Custom items can be deleted as well as added. There is no edit: delete and re-add.
- A custom name that clashes with a built-in name is rejected.
- Custom types appear in their own **Custom** group in the entity panel.

## 1. Data

`schema/custom.json` (created on first save; absent means no custom items):

```json
{
  "entity_types": [
    {"name": "CryptoWallet", "label": "Crypto wallet", "description": "A cryptocurrency wallet or address used by attackers."}
  ],
  "relations": [
    {"name": "pays-to", "inverse": "paid-by", "description": "a group or actor pays to a wallet",
     "pairs": [["ThreatGroup", "CryptoWallet"], ["ThreatActor", "CryptoWallet"]]}
  ]
}
```

Types in `pairs` are referenced by name, because custom types have no PDF ID. At load time, custom entity types get IDs from 101 upward in file order and the group `Custom`.

### Validation (on save)

**Entity type**
- `name`: matches `^[A-Z][A-Za-z0-9]{1,39}$`. It must be one word because it becomes a BIO label (`B-CryptoWallet`).
- `name` must not equal any existing entity type name (built-in or custom).
- `label`: 1–40 characters after trimming.
- `description`: 5–300 characters after trimming. The LLM prompt depends on it.

**Relation**
- `name` and `inverse`: each matches `^[a-z][a-z0-9-]{1,39}$`. `inverse` may equal `name` for a symmetric relation.
- Neither `name` nor `inverse` may equal any existing relation name or inverse name (built-in or custom).
- `description`: 5–300 characters.
- `pairs`: 1–50 `[source, target]` pairs. Every type must exist (built-in or custom), and duplicates are removed.

**Delete**
- Deleting an entity type still used in any custom relation's pairs is refused. The error names the relations that use it.
- Deleting an unknown name returns "not found".

**Writes**
- The server writes to a temporary file in the same directory, then atomically replaces `custom.json`.

## 2. Backend

### `custom_schema.py` (new)

This module holds pure functions over the custom data dict. The file and the loaded schema are passed in, so tests never touch the real file.

- `load_custom(path) -> dict`: returns an empty structure if the file is missing.
- `add_entity_type(custom, base_schema, item) -> dict`: raises `CustomSchemaError` with a message.
- `add_relation(custom, base_schema, item) -> dict`
- `delete_entity_type(custom, name) -> dict`
- `delete_relation(custom, name) -> dict`
- `save_custom(path, custom)`: atomic write.

`base_schema` here means the merged schema at the time of the call, which is what the uniqueness checks run against.

### `ontology.py`

- `load_schema()` merges the overlay at `CUSTOM_PATH`; `reload_schema()` clears the cache after a save. Custom relations are built with the same `Relation` dataclass. Custom types get `group="Custom"`.
- `load_base_schema()` loads the PDF schema only. The PDF-fidelity tests use it.
- `Schema.presets["Everything"]` is computed as all entity types, custom included.
- `Schema.is_custom(name)` reports whether a type or relation is custom (used by the API and UI).
- After a save, the API calls `reload_schema()`. The LLM extractor, validator, and `relations_for()` read `load_schema()` on each call, so they see the change immediately.

### API (`app.py`)

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/schema` | – | As now, plus `"custom": true/false` on each entity type and a `relations` list with custom flags |
| GET | `/custom` | – | Contents of `custom.json` |
| POST | `/custom/entity-types` | `{name, label, description}` | 201 with the updated custom data; 422 with a message on validation failure |
| DELETE | `/custom/entity-types/{name}` | – | 200 with the updated data; 404 if not found; 409 if in use |
| POST | `/custom/relations` | `{name, inverse, description, pairs}` | 201 or 422 |
| DELETE | `/custom/relations/{name}` | – | 200 or 404 |

The custom file path is `ontology.CUSTOM_PATH` (`schema/custom.json`), read at call time. A test fixture (`tests/conftest.py`, autouse) points it at a temporary file for every test, so no test reads or writes the real file.

A `schema/custom.json` that is not valid JSON makes schema loading fail with a clear error (`CustomFileError`) naming the file; the API returns it as a 500 with that message instead of a bare server error. Custom relation pairs that name a type which no longer exists are skipped at load time.

### Unchanged

The prompt, validator, rules, pipeline and output format need no code changes.

**Known limitations**
- Custom types have no few-shot examples in the prompt.
- In rules-only fallback, custom types are not found, because the rules only cover built-in pattern and dictionary types.

## 3. Page (`static/index.html`)

- The entity panel shows a **Custom** group, built from `/schema` like the others. Each custom type has a small × delete button with a confirm step inside the page (no browser `confirm()` dialog).
- A collapsible **Custom types** section below the panels has two forms:
  - **Add entity type:** name, label, description.
  - **Add relation:** name, inverse (defaults to the name), description, and a pair builder: source and target dropdowns listing all types, an "Add pair" button, and the pairs listed with × buttons to remove them.
- Custom relations are listed with a × delete button.
- After any successful add or delete, the page reloads `/schema`, re-renders the entity panel, and refreshes the relation panel. A newly added custom type starts selected.
- Validation errors from the server are shown inline under the form.
- Custom types get colours from a spare palette, assigned by position.

## 4. Testing

- `tests/test_custom_schema.py`: every validation rule (valid add, bad name format, clash with a built-in, clash with a custom, bad pair type, duplicate pairs removed, delete blocked when in use, delete not found, atomic save and reload).
- `tests/test_ontology.py`: the PDF-fidelity tests switch to `load_base_schema()`. New merge tests use a temporary custom file: custom type present with group Custom, custom relation allowed and inverse works, `relations_for` includes the custom relation, and "Everything" includes custom types.
- `tests/test_app.py`: the custom endpoints against a temporary file, including status codes; `/schema` custom flags; and after an add, `/relations` includes the custom relation.
- Validator and pipeline: one test showing a custom relation between a built-in and a custom type survives validation.
- Live check: add `CryptoWallet` and `pays-to`, then extract "Lazarus Group sent the ransom to the Monero wallet 4AdUndX…" with Mistral, and confirm the record is valid.

## Out of scope

- Editing custom items in place (delete and re-add).
- Keywords or regex for custom types.
- Extending built-in relations with new pairs.
- Authentication: anyone who can reach the server can change the custom schema. The server listens on localhost only.

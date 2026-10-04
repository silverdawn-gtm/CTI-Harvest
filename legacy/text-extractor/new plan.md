# Threat-Intel Extractor: Project Plan (v2)

## 1. Overview

A small localhost website that takes free text about cyber threats and returns structured JSON in the same structure as `dnrti-je.json`. It uses the **15 entity types and relations defined in `Entities_and_relations_1.pdf`**. Before running, the user **selects which entity types and relation types** should appear in the output.

The project is built in two phases:

- **Phase 1 (Hybrid):** regex and dictionaries find pattern-shaped entities. An LLM API (Mistral or Gemini) finds the remaining entities and all relations, constrained to the schema.
- **Phase 2 (Model):** fine-tuned local models replace the LLM once enough labeled data exists for the new schema.

## 2. Schema

### Entity types (15)

| ID | Type | BIO name | Main source in Phase 1 |
|---|---|---|---|
| 1 | Threat actor | `ThreatActor` | LLM |
| 2 | Threat group | `ThreatGroup` | ATT&CK dictionary + LLM |
| 3 | Malware | `Malware` | ATT&CK dictionary + LLM |
| 4 | Attack technique | `AttackTechnique` | ATT&CK dictionary, `T1566.001` IDs + LLM |
| 5 | Vulnerability | `Vulnerability` | `CVE-YYYY-NNNN` regex + LLM |
| 6 | Software | `Software` | LLM |
| 7 | Tool | `Tool` | ATT&CK dictionary + LLM |
| 8 | Organization | `Organization` | LLM |
| 9 | Attack pattern | `AttackPattern` | LLM |
| 10 | File/hash | `FileHash` | regex (hashes, file names) |
| 11 | Network infrastructure | `NetworkInfra` | regex (IPs, domains, URLs, defanged forms) |
| 12 | Asset/system | `Asset` | LLM |
| 13 | Security team | `SecurityTeam` | LLM |
| 14 | Time | `Time` | regex (dates, months, years) + LLM |
| 15 | Location | `Location` | country/region list + LLM |

### Relations

Each relation is stored once in `schema/schema.json` with its allowed (source type → target type) pairs from the PDF, plus an **inverse name**. The inverse is used when the source entity comes *after* the target in the sentence, as DNRTI did with `uses`/`usedBy`.

| Relation | Inverse | Allowed pairs (source → target) |
|---|---|---|
| alias-of | alias-of | 1↔2 |
| uses | used-by | 1→3,4,6,7,9 · 2→3,4,6\*,7,9 · 4→3,7 · 9→7 |
| targets | targeted-by | 1,2→8,12 · 4→5,12 |
| operates-in | operation-area-of | 1,2→15 |
| originated-from | origin-of | 1,2→15 |
| active-at | activity-time-of | 1,2→14 |
| variant-of | has-variant | 3→3 · 7→7 · 9→9 |
| sub-technique-of | has-sub-technique | 4→4 |
| drops | dropped-by | 3→10 |
| exploits | exploited-by | 3,7→5 |
| affects | affected-by | 3→6,12 · 5→6,12 |
| communicates-with | contacted-by | 3,7→11 |
| contains | contained-in | 6→5 |
| runs-on | hosts | 6→12 |
| remediated-by | remediates | 5→6 |
| belongs-to | owns | 11,12→8 |
| located-in | location-of | 11,12→15 · any→15 (generic) |
| monitored-by | monitors | 12→13 |
| indicates | indicated-by | 10→1,3 |
| downloads-from | download-source-of | 10→11 |
| utilized-by | utilizes | 11→1,2,3 |
| investigates | investigated-by | 13→1,2 |
| detects | detected-by | 13→3,5,9 |
| mitigates | mitigated-by | 13→5 · 13→4 (the PDF's "4 mitigated-by 13") |
| patches | patched-by | 13→12 |
| occurs-at | time-of | any→14 (generic) |

**Schema decisions to confirm:**

- \* "Threat group uses Software" is missing from the PDF but assumed to be an omission, so it is included.
- Generic relations (`located-in` for any entity, `occurs-at`) are used only when no specific relation fits. For example, a threat group with a location gets `operates-in` or `originated-from` first.
- The PDF's "4 mitigated-by 13" and "13 mitigates 5" are merged into one relation family.

## 3. Output Format

The output keeps the `dnrti-je.json` structure, with one record per sentence:

```json
{
  "text": "APT28 used X-Agent to target banks in Germany .",
  "entities": [[0, 1, "APT28", "ThreatGroup"], [2, 3, "X-Agent", "Malware"],
               [5, 6, "banks", "Organization"], [7, 8, "Germany", "Location"]],
  "relations": [["uses", 1, 0], ["targets", 2, 0], ["operates-in", 3, 0],
                ["noRelation", 2, 1], ["noRelation", 3, 1], ["noRelation", 3, 2]],
  "ent_labels": ["B-ThreatGroup", "O", "B-Malware", "O", "O", "B-Organization", "O", "B-Location", "O"]
}
```

- `entities` are `[start, end, surface, type]`. Token indices use whitespace split and are end-exclusive.
- `relations` are `[rel, i, j]` for **every** pair with `i > j`, meaning entity *j* → rel → entity *i*. The inverse name is used when the real source is entity *i*, and unrelated pairs get `noRelation`.
- The **selection filter** applies to everything. Entities of unselected types are removed, and their tokens are tagged `O`. Relations of unselected types become `noRelation`. Selecting a relation selects both its forward and inverse names.

## 4. Architecture

```
Browser (index.html)
   │  POST /extract { text, entity_types: [...], relation_types: [...] }
   ▼
FastAPI (app.py)
   ▼
pipeline.py
   1. tokenizer.py        split sentences, separate punctuation
   2. extractors/rules.py regex + dictionaries (selected types only)
   3. extractors/llm.py   entities not yet found (selected types only)
   4. merge               rule matches win on overlap
   5. extractors/llm.py   relations among found entities, as (source, relation, target)
   6. validator.py        drop anything not allowed by schema.json
   7. formatter.py        indices, BIO tags, all i>j pairs, inverse names, selection filter
   ▼
JSON list of records → highlights, relation table, raw JSON, download
```

```
project/
├── schema/schema.json        # single source of truth: types, relations, inverses, allowed pairs
├── data/
│   ├── dnrti-je.json
│   ├── attack/               # MITRE ATT&CK data (groups, software, techniques + aliases)
│   └── test_labeled.json     # hand-labeled test set in the new schema
├── build_dictionaries.py     # ATT&CK + country list → dictionaries/*.json
├── extractors/
│   ├── rules.py
│   ├── patterns.py           # regex definitions
│   ├── llm.py                # prompt building, JSON parsing, retries
│   ├── mistral.py            # thin client wrapper
│   └── gemini.py             # thin client wrapper
├── tokenizer.py
├── validator.py
├── formatter.py
├── pipeline.py
├── app.py
├── eval.py
├── static/index.html
├── .env                      # MISTRAL_API_KEY / GEMINI_API_KEY, LLM_PROVIDER=mistral|gemini
└── requirements.txt
```

The design has three rules:

- **Everything reads `schema.json`.** That includes the UI checkboxes, the LLM prompt, the validator and the formatter. Changing the schema means editing one file.
- **Extractors never produce indices, BIO tags or inverse names.** They return entity strings and directed triples, and `formatter.py` does the rest.
- **The LLM cannot invent relations.** The validator rejects any triple whose (source type, relation, target type) isn't in the schema.

## 5. Phase 1: Hybrid Version

1. **Schema.** Write `schema.json` from the PDF, including inverses and the decisions in section 2.
2. **Tokenizer and formatter.** Test them by rebuilding `dnrti-je.json` records exactly from their own entities and relations. This validates the indexing, BIO tags and pair enumeration.
3. **Regex patterns.**
   - File/hash: MD5, SHA1 and SHA256 hashes, and file names with executable or document extensions
   - Network infrastructure: IPv4 addresses, domains and URLs, including defanged forms (`hxxp`, `[.]`)
   - Vulnerability: CVE IDs
   - Attack technique: ATT&CK technique IDs
   - Time: dates, months and years
4. **Dictionaries.** Download the MITRE ATT&CK data from GitHub. It gives names and aliases for groups, malware, tools and techniques, and the aliases also produce `alias-of` relations. Add a country and region list for Location. Match case-insensitively, longest match first.
5. **LLM extractor.** The prompt contains only the selected entity types and the allowed relations between them, with short definitions and a few examples. It also lists the entities the rules already found, so the LLM only has to add missing ones and find relations. Use JSON mode: `response_format={"type": "json_object"}` for Mistral, or `response_mime_type="application/json"` plus `response_schema` for Gemini. Use temperature 0, and retry once on invalid JSON.
6. **Validator.** It drops unknown types and disallowed triples, discards entities that can't be located in the text, and applies the specific-over-generic rule.
7. **Web app.** Run it with `uvicorn app:app --reload` at `localhost:8000`.
8. **Evaluation.** Hand-label 50–100 sentences in the new schema, then measure entity F1 per type and relation F1 (excluding `noRelation`). DNRTI can additionally score the mapped entity types (see section 7).

## 6. Web UI

- **Text input:** a textarea plus an Extract button.
- **Entity type panel:** 15 checkboxes grouped as in the PDF (Actors, Malware & Tools, Techniques, Vulnerabilities & Assets, Indicators, Context), with Select all and Clear buttons.
- **Relation type panel:** this updates automatically, and a relation only appears when at least one of its allowed type pairs has both types selected.
- **Presets:**
  - "IOCs only": File/hash, Network infrastructure and Vulnerability
  - "Actors & targets": Threat actor, Threat group, Organization, Asset/system and Location
  - "Everything"
- **Output:** color-coded entity highlights, a relation table that hides `noRelation`, the raw JSON, and a JSON download.

## 7. Using the DNRTI Data

DNRTI uses a different schema, so it serves as partial data only, for evaluating entity types and later for training.

| DNRTI | New type |
|---|---|
| HackOrg | Threat group |
| Org | Organization |
| Area | Location |
| Time | Time |
| SamFile | File/hash |
| SecTeam | Security team |
| Exp | Vulnerability |
| OffAct, Way | Attack technique / Attack pattern (needs review) |
| Tool | Malware or Tool (split using the ATT&CK dictionary) |
| Features, Purp | no equivalent, dropped |

DNRTI's relations don't map to the new schema and cannot be used for evaluation.

## 8. Phase 2: Local Models

1. Grow the labeled data. Run Phase 1 on more reports, have a person correct the output, and add the mapped DNRTI entities.
2. Fine-tune a BERT-style NER model (e.g. SecureBERT) on the 15 types.
3. Train a relation classifier over entity pairs, with entity markers, restricted to the schema's allowed relations for each type pair.
4. Add `extractors/local.py` behind the same interface, then compare it with Phase 1 using `eval.py`.

## 9. What to Expect

- **Very reliable:** hashes, IPs, domains, CVEs, technique IDs and dates, because regex handles these.
- **Good:** well-known groups, malware and tools, through ATT&CK names and aliases. New names depend on the LLM.
- **Hardest:** the distinctions between actor and group, malware and tool, and technique and pattern. These are ambiguous even for human annotators.
- **Relations are the weakest part** and depend fully on the LLM. The schema validator removes invalid relations but cannot catch wrong valid ones.
- **Selection:** fewer selected types means a shorter prompt, so extraction is faster and cheaper, and usually more accurate.
- **Cost and speed:** it needs an API key and internet access, and takes a few seconds per request. Mistral and Gemini both have free tiers suitable for development.

## 10. Milestones

| # | Deliverable | Done when |
|---|---|---|
| 1 | `schema.json` | All PDF relations encoded, and schema decisions confirmed |
| 2 | Tokenizer + formatter + selection filter | DNRTI records rebuild exactly, and the filter removes the right items |
| 3 | Regex + ATT&CK dictionaries | Pattern types extracted correctly on sample reports |
| 4 | LLM extractor + validator | Valid, schema-compliant JSON for any input |
| 5 | Web UI with selection panels | End-to-end on localhost |
| 6 | Hand-labeled test set + `eval.py` | Baseline F1 per entity type and for relations |
| 7 | Local models (Phase 2) | Compared against the Phase 1 baseline |

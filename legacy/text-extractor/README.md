# Threat-Intel Extractor

A small web app that runs on your own computer and turns free text about cyber threats into structured JSON: **entities** (threat groups, malware, CVEs, IPs, domains, dates, …) and the **relations** between them (`APT28 uses X-Agent`, `X-Agent communicates-with evil[.]com`).

You paste a report, tick the entity and relation types you care about, and get:
- colour-coded highlights;
- a table of relations;
- the raw JSON, ready to download.

The output uses the record format of the DNRTI joint-extraction dataset (`dnrti-je.json`). Entities and relations follow a 15-type / 26-relation schema taken from `Entities_and_relations_1.pdf`, and you can add your own types and relations from the page.

Extraction is **hybrid**:
- **Regex patterns and MITRE ATT&CK dictionaries** find the entities with a predictable shape: hashes, IPs, domains, URLs, CVEs, technique IDs, dates, known groups, malware, tools and countries.
- **An LLM** (Mistral, Gemini or xAI Grok) finds everything else, plus all relations. The calls for different sentences run in parallel.
- **A validator** throws away any relation the schema does not allow, so the LLM cannot invent relation types.

---

## Contents

1. [Quick start](#1-quick-start)
2. [Configuration](#2-configuration)
3. [Using the web page](#3-using-the-web-page)
4. [Output format](#4-output-format)
5. [The schema](#5-the-schema)
6. [How extraction works](#6-how-extraction-works)
7. [Custom entity and relation types](#7-custom-entity-and-relation-types)
8. [HTTP API](#8-http-api)
9. [Project layout](#9-project-layout)
10. [Tests](#10-tests)
11. [Data: dictionaries and the DNRTI dataset](#11-data-dictionaries-and-the-dnrti-dataset)
12. [Security notes](#12-security-notes)
13. [Limitations and roadmap](#13-limitations-and-roadmap)
14. [Credits and licences of data sources](#14-credits-and-licences-of-data-sources)

---

## 1. Quick start

**You need:** Python 3.11 or newer, git, and an API key for **Mistral**, **Gemini** or **xAI Grok**. Mistral and Gemini have free tiers (see [Configuration](#2-configuration)).

### Clone

```bash
git clone https://github.com/silverdawn-gtm/Extractor.git text-extractor
cd text-extractor
```

> The repository is **private**: you need to be signed in to a GitHub account that has access. Git will ask you to sign in, or use an SSH key or personal access token.

### Create a virtual environment and install

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> If PowerShell refuses to run `Activate.ps1`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `.venv\Scripts\activate.bat` from `cmd`.

### Add your API key

Copy the example settings file and put your key in it:

```bash
cp .env.example .env        # Windows PowerShell: Copy-Item .env.example .env
```

Open `.env` and set `MISTRAL_API_KEY`. To use another provider, set `GEMINI_API_KEY` with `LLM_PROVIDER=gemini`, or `GROK_API_KEY` with `LLM_PROVIDER=grok`. `.env` is git-ignored, so your keys are never committed.

### Run

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open **http://localhost:8000** in your browser, paste some text, and press **Extract** (or Ctrl+Enter).

**Development option:** add `--reload` to restart the server automatically when code changes. On Windows, the reloader sometimes hangs and keeps serving old code; if it does, stop the server and start it again without `--reload`.

**Without an API key**, the app still runs. It uses the regex and dictionary rules only, and the page shows a warning saying so.

### Check the install

```bash
python -m pytest -q
```

All tests should pass. The tests that need the DNRTI dataset are skipped automatically when it is not present (see [section 11](#11-data-dictionaries-and-the-dnrti-dataset)). The tests never call an LLM API.

---

## 2. Configuration

All settings live in `.env`, in the project folder. `.env.example` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `mistral` | Which LLM to use: `mistral`, `gemini` or `grok`. |
| `LLM_PARALLEL` | `4` | How many sentences are sent to the LLM at the same time. `1` sends them one after another. |
| `MISTRAL_API_KEY` | – | Key from https://console.mistral.ai |
| `MISTRAL_MODEL` | `ministral-14b-latest` | First model to try. |
| `MISTRAL_FALLBACK_MODELS` | – | Comma-separated models to try if the first is rate-limited or unavailable, e.g. `ministral-8b-latest`. |
| `GEMINI_API_KEY` | – | Key from https://aistudio.google.com/apikey |
| `GEMINI_MODEL` | `gemini-3.8-flash` | First model to try. |
| `GEMINI_FALLBACK_MODELS` | – | e.g. `gemini-3.6-flash,gemini-2.5-flash` |
| `GROK_API_KEY` | – | Key from https://console.x.ai |
| `GROK_MODEL` | `grok-4-fast-non-reasoning` | First model to try. xAI renames models often; if this one is rejected, pick one from the model list in the xAI console. |
| `GROK_FALLBACK_MODELS` | – | Comma-separated fallback models. |

**Free-tier notes**

- **Mistral free ("Experiment") plan:** only the small Ministral models were usable; `mistral-small` and `mistral-medium` report a limit of 0 requests per minute. `ministral-14b-latest` allows about 30 requests/minute, and `ministral-8b-latest` about 180.
- **Gemini free tier:** about **20 requests per model per day**. The client moves to the next fallback model once a model's daily quota is used up. Quotas reset at midnight Pacific time.
- **Grok** is billed against xAI API credits; check your limits in the xAI console. It uses *structured outputs*, so like Gemini its replies are limited to the selected labels.
- **Request volume:** one sentence costs one LLM request. A 10-sentence report is 10 requests.
- **Parallel calls:** up to `LLM_PARALLEL` requests (default 4) are in flight at once, so long texts finish much sooner. Measured with Mistral on 6 sentences: **134 s one at a time, 36 s with 4 in parallel**. Running in parallel uses no extra quota. If a provider starts returning rate-limit errors, lower `LLM_PARALLEL`.

**How failures are handled:**
- **Rate limits and outages:** the client retries with back-off and then moves to the next fallback model.
- **The LLM fails completely** for a sentence: that sentence still gets the rule-based results, and the page shows a warning.

---

## 3. Using the web page

The page has four parts.

**Text box**
- Paste one or more sentences or paragraphs.
- The text is split into sentences, and each sentence becomes one output record.

**Entity types panel**
- The 15 schema types are grouped as Actors, Malware & Tools, Techniques, Vulnerabilities & Assets, Indicators and Context. Custom types appear in a **Custom** group.
- Hover over a type to see its definition. The coloured swatch is the highlight colour.
- **Presets:**
  - **IOCs only:** File/hash, Network infrastructure, Vulnerability.
  - **Actors & targets:** Threat actor, Threat group, Organization, Asset/system, Location.
  - **Everything:** all types, custom ones included.
- **Select all / Clear.**
- Your selection is remembered in your browser.

**Relations panel**
- Lists only the relations that are possible between the ticked entity types. For example, with only Threat group and Malware ticked you see `uses`, `alias-of` and `variant-of`, but not `targets`.
- Hover over a relation to see its allowed pairs.
- A relation you untick stays unticked when you change the entity types.

**Custom types** (collapsible). Add or delete your own entity types and relations; see [section 7](#7-custom-entity-and-relation-types).

**Results.** After **Extract** you get:
- **Warnings**, if any. For example, the LLM failed and a sentence was processed by the rules only.
- **Entities**: each sentence with its entities highlighted and labelled, plus a colour legend.
- **Relations**: a *Source → Relation → Target* table. `noRelation` pairs are hidden.
- **JSON**: the full records, with **Download JSON** and **Copy** buttons.

---

## 4. Output format

Each sentence becomes one record, in the structure of `dnrti-je.json`:

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

| Field | Meaning |
|---|---|
| `text` | The sentence, tokenized: punctuation is split into its own tokens (`banks , and` / `Germany .`), and possessives are split (`APT28 's`). Hashes, IPs, URLs, domains (including defanged ones such as `evil[.]com`), file names and IDs like `T1566.001` stay whole. |
| `entities` | `[start, end, surface, type]`. Token indices use a whitespace split and are end-exclusive. Sorted by position. |
| `relations` | `[relation, i, j]` for **every** pair of entities with `i > j`, ordered by `j` then `i`. It reads as *entity j → relation → entity i*. Pairs with no relation are `noRelation`. When the real source is the later entity, the relation's **inverse name** is used: "X-Agent is used by APT28" gives `["used-by", 1, 0]`. |
| `ent_labels` | One BIO tag per token (`B-Type`, `I-Type`, `O`). |

The download button saves a JSON **list** of these records.

---

## 5. The schema

The schema lives in `schema/schema.json`. It encodes `Entities_and_relations_1.pdf` exactly, plus a few documented decisions. Everything reads it: the page's checkboxes, the LLM prompt, the validator and the output. Your own additions go in a separate overlay file (see [section 7](#7-custom-entity-and-relation-types)).

### Entity types

| # | Type | Label | Group | What it covers |
|---|---|---|---|---|
| 1 | `ThreatActor` | Threat actor | Actors | An individual attacker, persona or unnamed actor (e.g. 'a Russian-speaking hacker', 'the operator'). Named APT groups are ThreatGroup. |
| 2 | `ThreatGroup` | Threat group | Actors | A named hacking group, APT or crime gang (APT28, Lazarus Group, FIN7, OilRig). |
| 3 | `Malware` | Malware | Malware & Tools | Malicious software: backdoors, RATs, trojans, ransomware, loaders (X-Agent, PlugX, WannaCry, Emotet). |
| 4 | `AttackTechnique` | Attack technique | Techniques | A specific adversary technique, usually a MITRE ATT&CK technique or ID (Spearphishing Attachment, T1566.001, credential dumping). |
| 5 | `Vulnerability` | Vulnerability | Vulnerabilities & Assets | A software weakness or exploit, including CVE IDs (CVE-2017-11882, a zero-day in Flash, EternalBlue). |
| 6 | `Software` | Software | Malware & Tools | Legitimate software or a product that is attacked, abused or vulnerable (Microsoft Office, Windows, Adobe Flash). |
| 7 | `Tool` | Tool | Malware & Tools | Dual-use or offensive tooling that is not malware itself (Mimikatz, PsExec, Impacket, PowerShell). |
| 8 | `Organization` | Organization | Context | A targeted or involved company, agency or sector (banks, government agencies, Microsoft, the energy sector). |
| 9 | `AttackPattern` | Attack pattern | Techniques | A general method or style of attack not tied to one technique (phishing, watering hole attacks, supply-chain attack, brute force). |
| 10 | `FileHash` | File/hash | Indicators | A file name, file sample or hash (MD5/SHA1/SHA256) (invoice.doc, svchost.exe, d41d8cd98f00b204e9800998ecf8427e). |
| 11 | `NetworkInfra` | Network infrastructure | Indicators | An IP address, domain, URL or server used in attacks, including defanged forms (185.12.45[.]6, evil[.]com, C2 server). |
| 12 | `Asset` | Asset/system | Vulnerabilities & Assets | A victim system, device or network (email servers, ICS systems, endpoints, domain controllers). |
| 13 | `SecurityTeam` | Security team | Context | A security vendor, research team or CERT (FireEye, Kaspersky Lab, Unit 42, US-CERT). |
| 14 | `Time` | Time | Context | A date, year, month or period (2017, March 2019, late 2018). |
| 15 | `Location` | Location | Context | A country, region, city or nationality (Russia, the Middle East, Ukrainian). |

### Relations

Each relation is stored **once**, in one direction, with an **inverse name** for the other direction. The formatter chooses the name from word order in the sentence.

| Relation | Inverse | Allowed source → target |
|---|---|---|
| `alias-of` | `alias-of` | ThreatActor → ThreatGroup, ThreatGroup → ThreatActor, ThreatGroup → ThreatGroup |
| `uses` | `used-by` | AttackPattern → Tool, AttackTechnique → Malware, AttackTechnique → Tool, ThreatActor → AttackPattern, ThreatActor → AttackTechnique, ThreatActor → Malware, ThreatActor → Software, ThreatActor → Tool, ThreatGroup → AttackPattern, ThreatGroup → AttackTechnique, ThreatGroup → Malware, ThreatGroup → Software, ThreatGroup → Tool |
| `targets` | `targeted-by` | AttackTechnique → Asset, AttackTechnique → Vulnerability, ThreatActor → Asset, ThreatActor → Organization, ThreatGroup → Asset, ThreatGroup → Organization |
| `operates-in` | `operation-area-of` | ThreatActor → Location, ThreatGroup → Location |
| `originated-from` | `origin-of` | ThreatActor → Location, ThreatGroup → Location |
| `active-at` | `activity-time-of` | ThreatActor → Time, ThreatGroup → Time |
| `variant-of` | `has-variant` | AttackPattern → AttackPattern, Malware → Malware, Tool → Tool |
| `sub-technique-of` | `has-sub-technique` | AttackTechnique → AttackTechnique |
| `drops` | `dropped-by` | Malware → FileHash |
| `exploits` | `exploited-by` | Malware → Vulnerability, Tool → Vulnerability |
| `affects` | `affected-by` | Malware → Asset, Malware → Software, Vulnerability → Asset, Vulnerability → Software |
| `communicates-with` | `contacted-by` | Malware → NetworkInfra, Tool → NetworkInfra |
| `contains` | `contained-in` | Software → Vulnerability |
| `runs-on` | `hosts` | Software → Asset |
| `remediated-by` | `remediates` | Vulnerability → Software |
| `belongs-to` | `owns` | Asset → Organization, NetworkInfra → Organization |
| `located-in` | `location-of` | Asset → Location, NetworkInfra → Location; *any type* → Location (generic) |
| `monitored-by` | `monitors` | Asset → SecurityTeam |
| `indicates` | `indicated-by` | FileHash → Malware, FileHash → ThreatActor |
| `downloads-from` | `download-source-of` | FileHash → NetworkInfra |
| `utilized-by` | `utilizes` | NetworkInfra → Malware, NetworkInfra → ThreatActor, NetworkInfra → ThreatGroup |
| `investigates` | `investigated-by` | SecurityTeam → ThreatActor, SecurityTeam → ThreatGroup |
| `detects` | `detected-by` | SecurityTeam → AttackPattern, SecurityTeam → Malware, SecurityTeam → Vulnerability |
| `mitigates` | `mitigated-by` | SecurityTeam → AttackTechnique, SecurityTeam → Vulnerability |
| `patches` | `patched-by` | SecurityTeam → Asset |
| `occurs-at` | `time-of` | *any type* → Time (generic) |

**Generic relations.** `occurs-at` (any type → Time) and the "any type" part of `located-in` are only used when no more specific relation fits. A threat group and a location, for example, get `operates-in` or `originated-from`, never `located-in`.

**Decisions on top of the PDF** (recorded in `schema/schema.json` under `assumptions` and `notes`):
- **Threat group `uses` Software** is added. The PDF only has it for Threat actor, which looks like an omission.
- **Threat group `alias-of` Threat group** is added, because ATT&CK aliases are group ↔ group (APT28 = Fancy Bear). The PDF only has actor ↔ group.
- **`mitigates` merges two PDF lines.** The PDF's "4 mitigated-by 13" and "13 mitigates 5" are one family, stored as `mitigates` (Security team → Attack technique / Vulnerability).
- **`sub-technique-of` uses hyphens.** The PDF writes `sub_technique_of`; hyphens match the other names.
- **The groups and definitions are this project's own.** The PDF does not define the entity types or group them.

---

## 6. How extraction works

```
Browser (static/index.html)
   │  POST /extract { text, entity_types, relation_types }
   ▼
FastAPI (app.py)
   ▼
pipeline.extract_records(), for each sentence:
   1. tokenizer.py            split into sentences; separate punctuation into tokens
   2. extractors/rules.py     regex patterns (extractors/patterns.py) → dates → ATT&CK/country
                              dictionaries (dictionaries/entities.json); selected types only
   3. extractors/llm.py       one LLM call per sentence, several sentences in parallel
                              (LLM_PARALLEL): the prompt lists the selected types, the relations
                              possible between them, and what the rules already found; the LLM
                              adds missing entities and all relations as (source, relation, target)
   4. merge                   LLM entities may only use tokens the rules left free (rules win)
   5. validator.py            drop unknown/unselected types, relations the schema does not allow,
                              and generic relations where a specific one fits
   6. formatter.py            token indices, BIO tags, every i > j pair, inverse names
   ▼
{ "records": [...], "warnings": [...] }
```

### 1. Tokenizer (`tokenizer.py`)
- Matches the DNRTI style. Brackets, quotes (curly ones included), commas, colons, semicolons and the sentence-final period become separate tokens, and possessive `'s` is split off.
- Periods inside tokens are kept, so `U.S.`, `3.5`, `evil[.]com` and `svchost.exe` stay whole.
- Sentence splitting does not break after abbreviations (`e.g.`, `U.S.`, `Jan.`, `Inc.`) or before a lowercase word.

### 2. Rules (`extractors/patterns.py`, `extractors/rules.py`)

**Regex, per token:**

| Pattern | Type |
|---|---|
| URLs (including `hxxp://` and defanged forms) | NetworkInfra |
| IPv4 addresses, with optional port and `[.]` | NetworkInfra |
| Domains with a real top-level domain (`Node.js` and `ASP.NET` are *not* domains) | NetworkInfra |
| MD5, SHA1 and SHA256 hashes | FileHash |
| File names with executable or document extensions | FileHash |
| `CVE-YYYY-NNNN` and `MS17-010` | Vulnerability |
| ATT&CK IDs such as `T1566.001` | AttackTechnique |

**Dates:**
- Years, month names, and full dates such as "12 March 2019", "Jan. 5, 2020" and "2016–2018".
- It skips "may be", a bare "May", and product names such as "Windows Server 2008".

**Dictionaries** (`dictionaries/entities.json`, built by `build_dictionaries.py`):
- **Sources:** MITRE ATT&CK groups, malware, tools and multi-word techniques, plus country names, demonyms ("Russian") and regions.
- **Matching:** names match case-sensitively, techniques case-insensitively, and the longest match wins ("Fancy Bear", not "Bear").
- **Aliases:** two names of the same ATT&CK group in one sentence get an `alias-of` relation.
- **Names left out on purpose** (each listed with its reason in `dictionaries/dropped.json`):
  - names ATT&CK lists under two types (`Carbanak` is both a group and malware);
  - very short or generic names (`at`, `Net`, `DNS`);
  - common words (`Page`, `Agenda`);
  - single-word technique names (`Malware`, `Domains`);
  - reconnaissance and resource-development sub-techniques, whose names describe targets ("Email Addresses") rather than techniques.

Each token belongs to at most one entity. Regex matches win over dates, and dates win over dictionary names.

### 3. LLM (`extractors/llm.py`, `extractors/mistral.py`, `extractors/gemini.py`, `extractors/grok.py`)
- **The prompt** is built from `prompts/extract_v2.txt` for the current selection. It includes:
  - the selected types with their definitions;
  - the possible relations with their allowed directions;
  - the entities the rules already found;
  - hand-written examples from `prompts/examples_v2.json`, cut down to the selected types.
- **The call:** temperature 0, JSON output. Gemini and Grok additionally get a JSON schema that limits the labels to the selected ones.
- **Parallel sentences:** the rules run for every sentence first. Then the LLM calls go out concurrently through a thread pool (`LLM_PARALLEL`, default 4), and the results are put back in sentence order. A failed call only affects its own sentence, which falls back to rules-only with a warning.
- **Shared client:** Mistral and Grok use the same OpenAI-style client (`extractors/openai_compat.py`), which handles retries, back-off, model fallback, and skipping models the account can't use.
- **Parsing:** invalid JSON is retried once. Unknown labels, and relations naming entities that aren't listed, are dropped.

### 4–6. Merge, validate, format
- **Merge:** rule matches win on overlap.
- **Validate:** `validator.py` checks every relation against `schema.json` (and your custom schema). An inverse name from the LLM (`used-by`) is turned back into the stored direction.
- **Format:** `formatter.py` builds the record described in [section 4](#4-output-format).

---

## 7. Custom entity and relation types

Open **Custom types** on the page to extend the schema.

**Add entity type**
- **Name:** one word starting with a capital letter, 2–40 characters (e.g. `CryptoWallet`). It becomes the BIO label `B-CryptoWallet`.
- **Label:** 1–40 characters.
- **Description:** 5–300 characters. The LLM relies on it to recognise the type, so make it specific.
- The new type appears, ticked, in the **Custom** group and in the "Everything" preset.

**Add relation**
- **Name and inverse:** lowercase letters, digits and hyphens (e.g. `pays-to` / `paid-by`). Leave the inverse empty for a symmetric relation.
- **Description.**
- **Allowed pairs:** one or more *source → target* pairs, chosen from all types, built-in or custom.

**Rules**
- Names must not clash with any existing type or relation, whatever the capitalisation (inverse names included).
- There can be at most 50 custom types and 50 custom relations, and at most 50 pairs per relation.
- Labels and descriptions may not contain line breaks or control characters. Descriptions go into the LLM prompt.
- A type that is still used by a custom relation cannot be deleted; delete the relation first. The × delete buttons need a second click to confirm.

**How custom types behave**
- Custom items are saved in `schema/custom.json`, a separate file merged over `schema/schema.json` at load time. The PDF schema file is never modified, and deleting `custom.json` resets everything.
- `custom.json` is git-ignored, because it's your local configuration. To version your custom types, remove its line from `.gitignore`.
- Custom types are found by the **LLM only**. There are no prompt examples for them, and they are not found when the app falls back to rules only.
- **Editing by hand:** you can edit `custom.json` directly (UTF-8, with or without a byte-order mark). Restart the server afterwards. A malformed file produces an error that names the problem.
- **Only from this computer:** changes are accepted only from the computer running the server; see [section 12](#12-security-notes).

---

## 8. HTTP API

All endpoints are served at `http://localhost:8000`.

| Method | Path | Body / query | Response |
|---|---|---|---|
| GET | `/` | – | The web page |
| GET | `/schema` | – | `{entity_types: [{name, label, group, description, custom}], relations: [{name, inverse, description, custom}], presets}` |
| GET | `/relations` | `?types=ThreatGroup,Malware` | `{relation: {inverse, description, pairs: [[source, target]]}}`, the relations possible for those types. 422 for unknown types. |
| POST | `/extract` | `{text, entity_types: [...], relation_types: [...] or null}` | `{records: [...], warnings: [...]}`. `relation_types: null` means every relation the types allow. 422 for unknown types or relations. |
| GET | `/custom` | – | Contents of `schema/custom.json` |
| POST | `/custom/entity-types` | `{name, label, description}` | 201 with the updated custom data; 422 with a message if invalid |
| DELETE | `/custom/entity-types/{name}` | – | 200; 404 not found; 409 still used by a relation |
| POST | `/custom/relations` | `{name, inverse, description, pairs}` | 201; 422 if invalid |
| DELETE | `/custom/relations/{name}` | – | 200; 404 not found |

The four `/custom` write endpoints return **403** unless the request comes directly from this computer.

**Example** (in Windows PowerShell, write `curl.exe`):

```bash
curl -X POST http://localhost:8000/extract -H "Content-Type: application/json" \
  -d '{"text": "APT28 used X-Agent against banks in Germany.", "entity_types": ["ThreatGroup", "Malware", "Organization", "Location"], "relation_types": null}'
```

---

## 9. Project layout

```
text-extractor/
├── app.py                    FastAPI server: page, /schema, /relations, /extract, /custom/*
├── pipeline.py               rules → LLM → merge → validate → format, per sentence
├── tokenizer.py              sentence splitting and DNRTI-style tokenization
├── formatter.py              spans, BIO tags, pair enumeration, inverse names, selection filter
├── validator.py              enforces the schema on entities and relations
├── ontology.py               loads schema/schema.json + schema/custom.json
├── custom_schema.py          add/delete/validate custom types; atomic saves
├── extractors/
│   ├── patterns.py           regex patterns and date finder
│   ├── rules.py              rule-based entity finder (regex + dictionaries)
│   ├── llm.py                schema-driven prompt, JSON parsing, retries
│   ├── openai_compat.py      shared client for OpenAI-style APIs (retries, backoff, model fallback)
│   ├── mistral.py            Mistral client (JSON mode)
│   ├── grok.py               xAI Grok client (structured outputs)
│   └── gemini.py             Gemini client (JSON schema, quota-aware fallback)
├── schema/
│   ├── schema.json           the 15 types / 26 relations from the PDF (+ documented decisions)
│   └── custom.json           your custom types (created on first save; git-ignored)
├── prompts/
│   ├── extract_v2.txt        LLM prompt template
│   └── examples_v2.json      hand-written examples in the schema
├── dictionaries/
│   ├── entities.json         built dictionary (ATT&CK + locations)
│   └── dropped.json          names deliberately left out, with reasons
├── build_dictionaries.py     rebuilds dictionaries/ from downloaded ATT&CK + country data
├── static/index.html         the web page (plain HTML/CSS/JS, no build step)
├── eval.py                   scoring helpers (entity F1 via seqeval, relation F1)
├── dnrti.py, dataset_checks.py, split_data.py
│                             DNRTI dataset support: labels, annotation-error checks, 80/10/10 split
├── tests/                    pytest suite (no network access needed)
├── docs/superpowers/         design spec and implementation plan for custom types
├── plan.md, new plan.md      project plans (v1 DNRTI version, v2 schema version)
├── Entities_and_relations_1.pdf   the schema source document
├── .env.example              settings template (copy to .env)
└── requirements.txt
```

---

## 10. Tests

```bash
python -m pytest -q
```

- The suite covers the tokenizer, formatter, schema loading and custom overlay, custom-type validation, regex patterns, dictionaries, the rules on a sample report, the LLM prompt and parsing (with fake replies), the Mistral, Gemini and Grok clients (with fake HTTP), the validator, the pipeline (including parallel calls, sentence order and per-sentence failures), and every API endpoint.
- **No test calls a real LLM or the network.**
- Tests never touch your real `schema/custom.json`: `tests/conftest.py` points it at a temporary file.
- **DNRTI tests** in `tests/test_dataset.py` run only when `data/dnrti-je.json` is present. They check that the tokenizer and formatter rebuild the dataset's clean records exactly.

---

## 11. Data: dictionaries and the DNRTI dataset

`data/` is **not** in the repository. The app does not need it to run.

### Rebuilding the dictionaries (optional)

`dictionaries/entities.json` is included in the repository. To rebuild it with the latest ATT&CK data:

```bash
mkdir -p data/attack data/countries
curl -L -o data/attack/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
curl -L -o data/countries/countries.json https://raw.githubusercontent.com/mledoze/countries/master/countries.json
python build_dictionaries.py
```

In Windows PowerShell, use `curl.exe` instead of `curl` (in PowerShell 5.1 `curl` means `Invoke-WebRequest`), and create the folders with `New-Item -ItemType Directory -Force data/attack, data/countries`.

The ATT&CK file is about 50 MB. The script prints how many names were kept and dropped for each type.

### DNRTI dataset (optional)

The v1 version of the project was built on the DNRTI joint entity/relation dataset (`dnrti-je.json`, 6,579 records). To use it again for testing, scoring or future training:
1. Put the file at `data/dnrti-je.json`.
2. Run `python dataset_checks.py`, which reports the annotation errors in the dataset (about 427 records have inconsistent spans or labels).
3. Run `python split_data.py`, which writes `data/train.json`, `dev.json` and `test.json` (80/10/10 split, seed 42).

---

## 12. Security notes

- **No login.** The server has no authentication. Run it on `127.0.0.1` (as shown above) and do not expose it to a network you don't trust.
- **Tunnels and port-forwarding expose it.** If you use a tunnel, port-forward or reverse proxy, anyone who can reach that address can run extractions **using your API keys**, which spends your quota or bill.
- **Custom types can only be changed from this computer.** `/custom` write requests are refused unless they come directly from the loopback address and carry no proxy-forwarding header, so a tunnel cannot change your schema.
- **Keys stay local.** API keys live only in `.env`, which is git-ignored. Never commit it. If a key has been shared anywhere (for example pasted into a chat), rotate it in the provider's console.

---

## 13. Limitations and roadmap

**Known limitations**
- **The hardest distinctions are left to the LLM:** threat actor vs group, malware vs tool, and technique vs pattern. Following ATT&CK, *Cobalt Strike is classified as Malware*, not Tool.
- **Relations depend entirely on the LLM.** The validator removes invalid relations but cannot catch a wrong *valid* one.
- **Relations only link entities within the same sentence.** Pronouns ("It contacted …") are not resolved.
- **Custom types rely on the LLM alone** and are not found in rules-only mode.
- **Speed:** each sentence takes a few seconds. Parallel calls help with long texts, but free tiers still limit how many sentences you can process per minute or per day.

**Roadmap** (from `new plan.md`):
1. **Milestone 6: evaluation.** Hand-label 50–100 sentences in the new schema, then measure entity F1 per type and relation F1 with `eval.py`. DNRTI can additionally score the entity types that map across (HackOrg → ThreatGroup, Area → Location, …).
2. **Milestone 7: local models (Phase 2).** Fine-tune a BERT-style NER model (e.g. SecureBERT) and a relation classifier restricted to the schema's allowed pairs, then compare them against the LLM baseline.

---

## 14. Credits and licences of data sources

- **MITRE ATT&CK®** (`dictionaries/`): group, malware, tool and technique names. © The MITRE Corporation. Used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
- **Country names and demonyms** (`dictionaries/`): from [mledoze/countries](https://github.com/mledoze/countries), licensed under the [ODbL](https://opendatacommons.org/licenses/odbl/1-0/).
- **DNRTI dataset:** not included. Obtain it from its original source and follow its licence.

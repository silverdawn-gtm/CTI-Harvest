# Threat-Intel Extractor: Project Plan

## 1. Overview

A small localhost website that takes free text about cyber threats and returns structured JSON in the same format as `dnrti-je.json` (the DNRTI joint entity/relation extraction dataset).

It is built in two phases:

- **Phase 1 (API):** an LLM API (Mistral or Gemini, whichever is chosen) extracts entities and relations, and our own code converts the result into the exact dataset format.
- **Phase 2 (Model):** fine-tuned local models trained on `dnrti-je.json` replace the API. The website and output format stay the same.

## 2. Target Output Format

Each input sentence produces one record:

```json
{
  "text": "The admin@338 has largely targeted organizations ...",
  "entities": [[1, 2, "admin@338", "HackOrg"], [5, 6, "organizations", "Org"]],
  "relations": [["targets", 1, 0]],
  "ent_labels": ["O", "B-HackOrg", "O", "O", "O", "B-Org", "..."]
}
```

| Field | Meaning |
|---|---|
| `text` | Tokenized sentence, with punctuation separated by spaces (`policy , typically`). |
| `entities` | `[start, end, surface, label]`. Token indices use whitespace split and are end-exclusive. |
| `relations` | `[rel, i, j]` for **every** entity pair with `i > j`. It reads as entity *j* → rel → entity *i*. Pairs with no link use `noRelation`. |
| `ent_labels` | BIO tag per token, derived from `entities`. |

**Entity labels (12):** HackOrg, Tool, Org, Area, Time, OffAct, SamFile, SecTeam, Exp, Way, Features, Purp

**Relation labels (16):** noRelation, targets, targetedBy, uses, usedBy, locatedAt, hasAttackTime, monitors, monitoredBy, hasCharacteristics, motivatedBy, motivates, associatedWith, discovers, discoveredBy, analyses

Some relations come in inverse pairs, such as `uses`/`usedBy`. The label is chosen by which entity appears first in the sentence.

## 3. Architecture

```
Browser (index.html)
   │  POST /extract  { "text": "..." }
   ▼
FastAPI (app.py)
   ▼
pipeline.py
   1. tokenize.py      → split sentences, separate punctuation into tokens
   2. extractor        → entities + relations   [Phase 1: Mistral/Gemini API | Phase 2: local models]
   3. formatter.py     → locate spans, build BIO tags, fill all i>j pairs, orient relations
   ▼
JSON list of records → rendered in the browser
```

```
project/
├── data/dnrti-je.json
├── app.py                # FastAPI server, serves static page + /extract
├── pipeline.py           # orchestrates tokenize → extract → format
├── tokenize.py
├── formatter.py          # the single source of truth for the output format
├── extractors/
│   ├── base.py           # common interface: extract(tokens) -> entities, relations
│   ├── llm_api.py        # Phase 1: shared prompt, parsing and validation
│   ├── mistral.py        # thin client wrapper
│   ├── gemini.py         # thin client wrapper
│   └── local_model.py    # Phase 2
├── prompts/extract.txt   # label definitions + few-shot examples from the dataset
├── eval.py               # scores any extractor against held-out data
├── static/index.html
├── .env                  # MISTRAL_API_KEY / GEMINI_API_KEY, EXTRACTOR=mistral|gemini|local
└── requirements.txt
```

The key design decision is that **the extractor never produces indices or BIO tags.** It returns entity strings and relations as (subject, relation, object). `formatter.py` does all the token counting, BIO tagging, pair enumeration, and direction handling. This keeps the output valid no matter which extractor is used, and switching phases is just a config change.

## 4. Phase 1: API Version

1. **Data split.** Split `dnrti-je.json` into train/dev/test sets (roughly 80/10/10) with a fixed seed. Few-shot examples come only from the train set, and scores come only from the test set.
2. **Tokenizer.** Match the dataset style by separating punctuation into its own tokens. Validate by re-tokenizing the dataset's own text and checking that it comes out unchanged.
3. **Formatter.** Build this first and test it by rebuilding every dataset record from its own entities and relations. The output must match the file exactly.
4. **LLM extractor.** The prompt contains the label definitions and 5–10 train examples. The model returns strict JSON of entities and directed triples. Use each provider's JSON mode: Mistral's `response_format={"type": "json_object"}`, or Gemini's `response_mime_type="application/json"` with a `response_schema`. Validate the JSON, drop unknown labels, and retry once on a parse error. The prompt and parsing code are shared, so each provider needs only a small client wrapper. This also makes it easy to compare Mistral and Gemini on the test set before committing to one.
5. **Span matching.** Map each returned entity string to token positions. Handle repeated strings (take the next unused occurrence), and discard entities that can't be found in the text.
6. **Web app.** The page has a textarea, an Extract button, color-coded entity highlights, a relation table (hiding `noRelation`), a raw JSON view, and a download button. Run it with `uvicorn app:app --reload` and open `localhost:8000`.
7. **Evaluation.** Measure entity F1 (seqeval) and relation F1 (excluding `noRelation`) on the test set. Record these numbers as the baseline for Phase 2.

## 5. Phase 2: Local Model Version

1. **NER model.** Fine-tune a BERT-style model (`bert-base-cased` or a security-domain model such as SecureBERT) as a token classifier on `ent_labels`.
2. **Relation model.** Build a pair classifier that uses entity marker tokens (`[E1]...[/E1]`, `[E2]...[/E2]`) and predicts one of the 16 relation labels. Because `noRelation` makes up about 55% of pairs, use class weights or downsampling.
3. **Plug in.** Implement `extractors/local_model.py` behind the same interface, then set `EXTRACTOR=local`.
4. **Compare.** Run `eval.py` on the same test split and keep whichever approach scores better, or use both, for example local NER with the LLM handling relations.

## 6. What to Expect

**Phase 1 strengths:** It works within a day or two, with no GPU or training needed. It handles unfamiliar phrasing reasonably well.

**Phase 1 weaknesses:**
- It needs an API key and internet access, costs a small amount per request (both providers have free tiers suitable for development, subject to rate limits), and takes a few seconds per call.
- It will not match the dataset's annotation habits exactly, such as where span boundaries fall or when a generic phrase like "organizations" counts as an Org. Scores against the dataset will be lower than the output quality looks to a human reader.
- Results can vary slightly between runs, so use temperature 0 to keep them consistent.

**Phase 2 strengths:** It runs offline, is free and fast per request, and follows the annotation conventions closely. It should outperform the API on the dataset's own metrics.

**Phase 2 weaknesses:** It needs training time (best on a GPU, though CPU is feasible and slow). It's also weaker on text that looks very different from the training reports.

**Known data quirks:** 80 records have no entities, and 544 have no relations. The data must be split on any whitespace, not single spaces, or 582 spans misalign.

## 7. Milestones

| # | Deliverable | Done when |
|---|---|---|
| 1 | Data split + tokenizer + formatter | Dataset records rebuild exactly |
| 2 | Mistral/Gemini extractor | Valid JSON for any input text |
| 3 | Web UI on localhost | Paste text, see highlights and JSON, download |
| 4 | Evaluation script | Baseline F1 scores recorded |
| 5 | Local NER + RE models | Test scores compared to baseline |
| 6 | Switchable extractor | `EXTRACTOR=mistral`, `gemini` or `local` all work |

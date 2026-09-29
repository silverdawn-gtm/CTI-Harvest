"""Orchestrates tokenize -> rules -> LLM -> merge -> validate -> format (schema/schema.json)."""
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

from formatter import format_record, locate_spans, resolve_triples
from tokenizer import split_sentences, tokenize
from validator import validate

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def extract_records(text, llm, matcher, entity_types, relation_types=None):
    """Returns (records, warnings). With llm=None, or if the LLM call fails, only the rules run."""
    records, warnings = [], []
    for n, sentence in enumerate(split_sentences(text), 1):
        tokens = tokenize(sentence)
        rule_spans, rule_triples = matcher.find(tokens, entity_types)
        llm_entities, llm_triples = [], []
        if llm is not None:
            try:
                llm_entities, llm_triples = llm.extract(tokens, entity_types, relation_types, known=rule_spans)
            except Exception as err:
                warnings.append(f"sentence {n}: LLM failed ({str(err)[:200]}); rules only")
        # rule spans win: LLM entities may only use tokens the rules left free
        spans = sorted(rule_spans + locate_spans(tokens, llm_entities, taken=rule_spans), key=lambda s: s[0])
        position = {(s[0], s[1]): k for k, s in enumerate(spans)}
        triples = [(position[tuple(rule_spans[a][:2])], rel, position[tuple(rule_spans[b][:2])])
                   for a, rel, b in rule_triples]
        triples += resolve_triples(spans, llm_triples)
        kept, valid, _ = validate(spans, triples, entity_types, relation_types)
        records.append(format_record(tokens, kept, valid))
    return records, warnings


def _complete_for(name):
    if name == "gemini":
        from extractors import gemini as client
        default = "gemini-3.8-flash"
    elif name == "mistral":
        from extractors import mistral as client
        default = "ministral-14b-latest"
    else:
        raise ValueError(f"unknown LLM provider: {name!r} (supported: gemini, mistral)")
    prefix = name.upper()
    models = [os.environ.get(f"{prefix}_MODEL", default)]
    models += [m.strip() for m in os.environ.get(f"{prefix}_FALLBACK_MODELS", "").split(",") if m.strip()]
    return client.make_complete(os.environ[f"{prefix}_API_KEY"], models)


@lru_cache(maxsize=None)
def get_llm_extractor(provider=None):
    """Schema-driven LLM extractor for LLM_PROVIDER (mistral or gemini)."""
    from extractors.llm import SchemaLLMExtractor
    provider = provider or os.environ.get("LLM_PROVIDER", "mistral")
    return SchemaLLMExtractor(_complete_for(provider))

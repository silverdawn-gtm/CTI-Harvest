"""Orchestrates tokenize -> rules -> LLM -> merge -> validate -> format (schema/schema.json)."""
import os
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

from formatter import format_record, locate_spans, resolve_triples
from tokenizer import split_sentences, tokenize
from validator import validate

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


DEFAULT_PARALLEL = 4


def _parallelism(parallel):
    if parallel is None:
        parallel = int(os.environ.get("LLM_PARALLEL", DEFAULT_PARALLEL))
    return max(1, parallel)


def extract_records(text, llm, matcher, entity_types, relation_types=None, parallel=None):
    """Returns (records, warnings). With llm=None, or if the LLM call fails, only the rules run.

    The rules run for every sentence first; then the LLM calls run concurrently, up to
    `parallel` at a time (default: LLM_PARALLEL, else 4). Output keeps sentence order.
    """
    sentences = []
    for sentence in split_sentences(text):
        tokens = tokenize(sentence)
        sentences.append((tokens, *matcher.find(tokens, entity_types)))

    def ask_llm(item):
        tokens, rule_spans, _ = item
        try:
            return llm.extract(tokens, entity_types, relation_types, known=rule_spans), None
        except Exception as err:
            return ([], []), err

    if llm is None or not sentences:
        answers = [(([], []), None)] * len(sentences)
    else:
        with ThreadPoolExecutor(max_workers=min(_parallelism(parallel), len(sentences))) as pool:
            answers = list(pool.map(ask_llm, sentences))  # map keeps input order

    records, warnings = [], []
    for n, ((tokens, rule_spans, rule_triples), ((llm_entities, llm_triples), err)) in enumerate(
            zip(sentences, answers), 1):
        if err is not None:
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
    elif name == "grok":
        from extractors import grok as client
        default = "grok-4-fast-non-reasoning"
    else:
        raise ValueError(f"unknown LLM provider: {name!r} (supported: gemini, mistral, grok)")
    prefix = name.upper()
    models = [os.environ.get(f"{prefix}_MODEL", default)]
    models += [m.strip() for m in os.environ.get(f"{prefix}_FALLBACK_MODELS", "").split(",") if m.strip()]
    return client.make_complete(os.environ[f"{prefix}_API_KEY"], models)


@lru_cache(maxsize=None)
def get_llm_extractor(provider=None):
    """Schema-driven LLM extractor for LLM_PROVIDER (mistral, gemini or grok)."""
    from extractors.llm import SchemaLLMExtractor
    provider = provider or os.environ.get("LLM_PROVIDER", "mistral")
    return SchemaLLMExtractor(_complete_for(provider))

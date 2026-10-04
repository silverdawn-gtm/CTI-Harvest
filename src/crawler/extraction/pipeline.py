"""Document text in, ontology-checked entities and relations out.

Per sentence: tokenize, run the rules, then ask the LLM for what the rules did not find.
Rule spans win any overlap, so the LLM can add entities but never relabel a regex or
dictionary hit. The merged result goes through the validator, and survivors are mapped back
to character offsets in the original text.
"""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from crawler.extraction.formatter import locate_spans, resolve_triples, token_offsets
from crawler.extraction.ontology import Ontology
from crawler.extraction.rules import RuleMatcher
from crawler.extraction.spans import Entity, IndexTriple, Span, SurfaceTriple
from crawler.extraction.tokenizer import split_sentences, tokenize
from crawler.extraction.validator import validate


class SentenceExtractor(Protocol):
    async def extract(
        self, sentence: str, known: Sequence[Span] = ()
    ) -> tuple[list[Entity], list[SurfaceTriple]]: ...


@dataclass(frozen=True)
class EntityMention:
    id: int
    text: str
    type: str
    start: int  # character offsets into the document text: text == document[start:end]
    end: int
    sentence: int
    origin: Literal["rules", "llm"]


@dataclass(frozen=True)
class RelationTriple:
    source: int  # EntityMention.id
    relation: str
    target: int
    sentence: int


@dataclass(frozen=True)
class DocumentExtraction:
    entities: tuple[EntityMention, ...]
    relations: tuple[RelationTriple, ...]
    sentences: int
    llm_failures: int
    warnings: tuple[str, ...] = ()
    dropped: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Sentence:
    index: int
    start: int  # character offset of the sentence in the document
    tokenized: str
    offsets: list[tuple[int, int]]  # per token, relative to the sentence
    rule_spans: list[Span]
    rule_triples: list[IndexTriple]


def _prepare(text: str, matcher: RuleMatcher, ontology: Ontology) -> list[_Sentence]:
    sentences: list[_Sentence] = []
    cursor = 0
    for index, sentence in enumerate(split_sentences(text)):
        # split_sentences returns slices of text.strip(), so each is found at or after cursor.
        start = text.find(sentence, cursor)
        cursor = start + len(sentence)
        tokenized = tokenize(sentence)
        spans, triples = matcher.find(tokenized, ontology.entity_names)
        offsets = token_offsets(sentence, tokenized.split())
        sentences.append(_Sentence(index, start, tokenized, offsets, spans, triples))
    return sentences


async def extract_text(
    text: str,
    matcher: RuleMatcher,
    ontology: Ontology,
    llm: SentenceExtractor | None = None,
) -> DocumentExtraction:
    sentences = _prepare(text, matcher, ontology)

    async def ask(s: _Sentence) -> tuple[list[Entity], list[SurfaceTriple], Exception | None]:
        if llm is None:
            return [], [], None
        try:
            entities, triples = await llm.extract(s.tokenized, known=s.rule_spans)
        except Exception as exc:  # noqa: BLE001 - one bad sentence must not sink the document
            return [], [], exc
        return entities, triples, None

    answers = await asyncio.gather(*(ask(s) for s in sentences))

    entities: list[EntityMention] = []
    relations: list[RelationTriple] = []
    warnings: list[str] = []
    dropped: list[str] = []
    failures = 0

    for s, (llm_entities, llm_triples, error) in zip(sentences, answers, strict=True):
        if error is not None:
            failures += 1
            warnings.append(
                f"sentence {s.index}: LLM failed "
                f"({type(error).__name__}: {str(error)[:200]}); rules only"
            )

        from_rules = {(span[0], span[1]) for span in s.rule_spans}
        spans = sorted(
            s.rule_spans + locate_spans(s.tokenized, llm_entities, taken=s.rule_spans),
            key=lambda span: span[0],
        )
        position = {(span[0], span[1]): k for k, span in enumerate(spans)}
        triples: list[IndexTriple] = [
            (
                position[(s.rule_spans[a][0], s.rule_spans[a][1])],
                rel,
                position[(s.rule_spans[b][0], s.rule_spans[b][1])],
            )
            for a, rel, b in s.rule_triples
        ]
        triples += resolve_triples(spans, llm_triples)

        kept, valid, removed = validate(spans, triples, ontology)
        dropped += [f"sentence {s.index}: {reason}" for reason in removed]

        base = len(entities)
        for start_token, end_token, _surface, type_ in kept:
            start = s.start + s.offsets[start_token][0]
            end = s.start + s.offsets[end_token - 1][1]
            origin: Literal["rules", "llm"] = (
                "rules" if (start_token, end_token) in from_rules else "llm"
            )
            entities.append(
                EntityMention(len(entities), text[start:end], type_, start, end, s.index, origin)
            )
        relations += [RelationTriple(base + a, rel, base + b, s.index) for a, rel, b in valid]

    return DocumentExtraction(
        tuple(entities),
        tuple(relations),
        len(sentences),
        failures,
        tuple(warnings),
        tuple(dropped),
    )

"""Shapes passed between the extraction stages."""

from typing import Any

# [start_token, end_token, surface, entity_type]: a list, because the rules, the LLM merge and
# the validator all read and compare spans positionally (the DNRTI format they came from).
Span = list[Any]
# (source_span_index, relation, target_span_index)
IndexTriple = tuple[int, str, int]
# (entity_text, entity_type)
Entity = tuple[str, str]
# (source_text, relation, target_text)
SurfaceTriple = tuple[str, str, str]

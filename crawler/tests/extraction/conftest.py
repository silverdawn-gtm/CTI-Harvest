from pathlib import Path

import pytest

from crawler.extraction.ontology import Ontology, load_ontology

SHIPPED_ONTOLOGY = Path(__file__).resolve().parents[2] / "config" / "ontology.json"


@pytest.fixture(scope="session")
def ontology() -> Ontology:
    return load_ontology(SHIPPED_ONTOLOGY)

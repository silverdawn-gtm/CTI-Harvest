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

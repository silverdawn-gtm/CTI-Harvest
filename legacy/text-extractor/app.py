"""FastAPI server: serves the page, the schema, and POST /extract.

Run: uvicorn app:app --reload   then open http://localhost:8000
"""
import os
import threading
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

import ontology
from custom_schema import (CustomSchemaError, InUse, NotFound, add_entity_type, add_relation,
                           delete_entity_type, delete_relation, load_custom, save_custom)
from extractors.rules import load_matcher
from ontology import load_schema
from pipeline import extract_records, get_llm_extractor

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Threat-Intel Extractor")


@app.exception_handler(ontology.CustomFileError)
def custom_file_error(request: Request, err: ontology.CustomFileError):
    return JSONResponse(status_code=500, content={"detail": str(err)})


class ExtractRequest(BaseModel):
    text: str
    entity_types: list[str]
    relation_types: Optional[list[str]] = None  # None: every relation the types allow


class EntityTypeIn(BaseModel):
    name: str
    label: str
    description: str


class RelationIn(BaseModel):
    name: str
    inverse: str = ""          # empty: symmetric (same as name)
    description: str
    pairs: list[list[str]]


def llm_dep():
    """(extractor or None, warning or None)."""
    provider = os.environ.get("LLM_PROVIDER", "mistral")
    try:
        return get_llm_extractor(provider), None
    except KeyError:
        return None, f"no API key for {provider} (set {provider.upper()}_API_KEY in .env); rules only"


def matcher_dep():
    return load_matcher()


LOOPBACK = {"127.0.0.1", "::1"}
PROXY_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")


def local_only(request: Request):
    """Custom types change what every user's extraction does, so only this computer may edit them.

    Requests relayed by a tunnel or proxy (which arrive from 127.0.0.1 but carry a
    forwarding header) are refused too.
    """
    host = request.client.host if request.client else ""
    if host not in LOOPBACK or any(h in request.headers for h in PROXY_HEADERS):
        raise HTTPException(status_code=403,
                            detail="custom types can only be changed from this computer (open http://localhost:8000)")


def _check_types(types):
    known = {t.name for t in load_schema().entity_types}
    unknown = sorted(set(types) - known)
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown entity types: {unknown}")


def _check_relations(relations):
    schema = load_schema()
    known = {n for r in schema.relations for n in (r.name, r.inverse)}
    unknown = sorted(set(relations) - known)
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown relation types: {unknown}")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/schema")
def schema():
    s = load_schema()
    return {
        "entity_types": [{"name": t.name, "label": t.label, "group": t.group, "description": t.description,
                          "custom": s.is_custom(t.name)} for t in s.entity_types],
        "relations": [{"name": r.name, "inverse": r.inverse, "description": r.description,
                       "custom": s.is_custom(r.name)} for r in s.relations],
        "presets": s.presets,
    }


@app.get("/relations")
def relations(types: str = Query("")):
    selected = [t for t in types.split(",") if t]
    _check_types(selected)
    s = load_schema()
    descriptions = {r.name: (r.inverse, r.description) for r in s.relations}
    return {name: {"inverse": descriptions[name][0], "description": descriptions[name][1],
                   "pairs": [list(p) for p in pairs]}
            for name, pairs in s.relations_for(set(selected)).items()}


@app.post("/extract")
def extract(request: ExtractRequest, llm_setup=Depends(llm_dep), matcher=Depends(matcher_dep)):
    _check_types(request.entity_types)
    relation_types = None if request.relation_types is None else set(request.relation_types)
    if relation_types is not None:
        _check_relations(relation_types)
    llm, setup_warning = llm_setup
    records, warnings = extract_records(request.text, llm, matcher, set(request.entity_types), relation_types)
    return {"records": records, "warnings": ([setup_warning] if setup_warning else []) + warnings}


_custom_lock = threading.Lock()  # endpoints run in a thread pool; one read-change-save at a time


def _change(change):
    """Apply a change to schema/custom.json, save it, and reload the schema."""
    path = ontology.CUSTOM_PATH
    with _custom_lock:
        try:
            custom = change(load_custom(path))
        except NotFound as err:
            raise HTTPException(status_code=404, detail=str(err))
        except InUse as err:
            raise HTTPException(status_code=409, detail=str(err))
        except CustomSchemaError as err:
            raise HTTPException(status_code=422, detail=str(err))
        save_custom(path, custom)
        ontology.reload_schema()
        return custom


@app.get("/custom")
def get_custom():
    return load_custom(ontology.CUSTOM_PATH)


@app.post("/custom/entity-types", status_code=201, dependencies=[Depends(local_only)])
def post_custom_entity_type(item: EntityTypeIn):
    return _change(lambda custom: add_entity_type(custom, load_schema(), item.model_dump()))


@app.delete("/custom/entity-types/{name}", dependencies=[Depends(local_only)])
def delete_custom_entity_type(name: str):
    return _change(lambda custom: delete_entity_type(custom, name))


@app.post("/custom/relations", status_code=201, dependencies=[Depends(local_only)])
def post_custom_relation(item: RelationIn):
    return _change(lambda custom: add_relation(custom, load_schema(), item.model_dump()))


@app.delete("/custom/relations/{name}", dependencies=[Depends(local_only)])
def delete_custom_relation(name: str):
    return _change(lambda custom: delete_relation(custom, name))

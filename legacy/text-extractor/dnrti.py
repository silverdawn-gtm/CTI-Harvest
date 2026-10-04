"""The DNRTI (dnrti-je.json) label set, used by the v1 extractor and dataset checks.

The v2 schema lives in schema/schema.json (see ontology.py).
"""
ENTITY_LABELS = [
    "HackOrg", "Tool", "Org", "Area", "Time", "OffAct",
    "SamFile", "SecTeam", "Exp", "Way", "Features", "Purp",
]
RELATION_LABELS = [
    "noRelation", "targets", "targetedBy", "uses", "usedBy", "locatedAt", "hasAttackTime",
    "monitors", "monitoredBy", "hasCharacteristics", "motivatedBy", "motivates",
    "associatedWith", "discovers", "discoveredBy", "analyses",
]

_FORWARD = {
    "targets": "targetedBy",
    "uses": "usedBy",
    "monitors": "monitoredBy",
    "motivates": "motivatedBy",
    "discovers": "discoveredBy",
}
_BACKWARD = {v: k for k, v in _FORWARD.items()}


def inverse(relation):
    """The label for the same relation read the other way; labels without a pair map to themselves."""
    return _FORWARD.get(relation) or _BACKWARD.get(relation) or relation


def family(relation):
    """The forward name of a relation's pair (usedBy -> uses)."""
    return _BACKWARD.get(relation, relation)

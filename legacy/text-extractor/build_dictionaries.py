"""Build dictionaries/entities.json from MITRE ATT&CK and a country list.

Sources (downloaded once, not kept in version control):
  data/attack/enterprise-attack.json
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
  data/countries/countries.json
    https://raw.githubusercontent.com/mledoze/countries/master/countries.json

Usage: python build_dictionaries.py
Writes dictionaries/entities.json (kept) and dictionaries/dropped.json (with reasons).
"""
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "dictionaries"

STIX_TYPES = {"intrusion-set": "ThreatGroup", "malware": "Malware", "tool": "Tool",
              "attack-pattern": "AttackTechnique"}

# Names that are ordinary words in threat reports (found as lowercase words in DNRTI)
STOPLIST = {"Agenda", "Expand", "Page", "Wiper", "Play", "Remote", "Carbon", "Epic", "Proton", "Rover",
            "Equation"}  # "Equation" is mostly "Equation Editor"; the group is added as "Equation Group"
EXTRA_ALIASES = {"G0020": ["Equation Group"]}
# Technique names that are ordinary phrases or name software/languages rather than a technique
TECHNIQUE_STOPLIST = {"Visual Basic", "Malicious File", "Remote Desktop Protocol", "Control Panel",
                      "Windows Service"}
# Sub-techniques of these tactics name what is gathered or acquired ("Email Addresses", "Botnet")
TARGET_TACTICS = {"reconnaissance", "resource-development"}
# Short all-caps names that are protocols or file types, not software
GENERIC_SHORT = {"DNS", "SSH", "DLL", "VNC", "MMC", "FTP", "RDP", "SMB", "LV", "PS1"}

REGIONS = [
    "Middle East", "Europe", "Asia", "Africa", "Southeast Asia", "South Asia", "East Asia", "Central Asia",
    "Eastern Europe", "Western Europe", "Central Europe", "North America", "South America", "Latin America",
    "Persian Gulf", "Gulf region", "Asia-Pacific", "APAC", "EMEA", "Balkans", "Caucasus", "Scandinavia",
    "Oceania", "Caribbean", "Korean Peninsula", "Middle Eastern", "European", "Asian", "African",
]
SHORT_LOCATIONS = {"US", "USA", "UK", "UAE", "PRC", "DPRK", "ROK", "EU"}


def _attack_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), None)


def attack_entries(bundle):
    entries = []
    for obj in bundle["objects"]:
        type_ = STIX_TYPES.get(obj.get("type"))
        if not type_ or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        aliases = obj.get("aliases", []) + obj.get("x_mitre_aliases", [])
        aliases += EXTRA_ALIASES.get(_attack_id(obj), [])
        tactics = {p["phase_name"] for p in obj.get("kill_chain_phases", [])}
        target_only = bool(obj.get("x_mitre_is_subtechnique")) and bool(tactics) and tactics <= TARGET_TACTICS
        for name in dict.fromkeys([obj["name"], *aliases]):
            entry = {"name": name, "type": type_, "id": _attack_id(obj)}
            if target_only:
                entry["target_only"] = True
            entries.append(entry)
    return entries


def location_entries(countries, regions=REGIONS):
    names = []
    for c in countries:
        demonyms = c.get("demonyms", {}).get("eng", {})
        spellings = [s for s in c.get("altSpellings", []) if len(s) > 3 or s in SHORT_LOCATIONS]
        names += [(n, c.get("cca2")) for n in
                  [c["name"]["common"], c["name"]["official"], *spellings, *demonyms.values()]]
    names += [(r, "region") for r in regions]
    seen, entries = set(), []
    for name, id_ in names:
        if name and name not in seen:
            seen.add(name)
            entries.append({"name": name, "type": "Location", "id": id_, "case_sensitive": True})
    return entries


def _drop_reason(entry, types_of):
    name, type_ = entry["name"], entry["type"]
    if len(types_of[name]) > 1:
        return f"ambiguous: {sorted(types_of[name])}"
    if name in STOPLIST:
        return "common word"
    if len(name) <= 3 and (not name.isupper() or name in GENERIC_SHORT):
        return "too short or generic"
    if type_ == "AttackTechnique" and " " not in name:
        return "single-word technique name"
    if entry.get("target_only"):
        return "names a target or resource (recon/resource-development sub-technique)"
    if name in TECHNIQUE_STOPLIST:
        return "generic technique name"
    return None


def clean_entries(entries):
    types_of = collections.defaultdict(set)
    for e in entries:
        types_of[e["name"]].add(e["type"])
    kept, dropped, seen = [], [], set()
    for e in entries:
        reason = _drop_reason(e, types_of)
        if reason:
            dropped.append({**e, "reason": reason})
        elif (e["name"], e["type"]) not in seen:
            seen.add((e["name"], e["type"]))
            kept.append({"name": e["name"], "type": e["type"], "id": e["id"],
                         "case_sensitive": e["type"] != "AttackTechnique"})
    return kept, dropped


def main():
    bundle = json.loads((ROOT / "data/attack/enterprise-attack.json").read_text(encoding="utf-8"))
    countries = json.loads((ROOT / "data/countries/countries.json").read_text(encoding="utf-8"))
    kept, dropped = clean_entries(attack_entries(bundle))
    kept += location_entries(countries)
    OUT.mkdir(exist_ok=True)
    (OUT / "entities.json").write_text(json.dumps(kept, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT / "dropped.json").write_text(json.dumps(dropped, ensure_ascii=False, indent=1), encoding="utf-8")
    counts = collections.Counter(e["type"] for e in kept)
    print(f"kept {len(kept)} names: {dict(counts)}")
    print(f"dropped {len(dropped)}: {dict(collections.Counter(d['reason'].split(':')[0] for d in dropped))}")


if __name__ == "__main__":
    main()

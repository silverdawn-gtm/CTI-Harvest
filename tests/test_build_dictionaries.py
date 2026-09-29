from build_dictionaries import attack_entries, clean_entries, location_entries


def stix(type_, name, ext_id, aliases=(), alias_field="aliases", **extra):
    obj = {"type": type_, "name": name,
           "external_references": [{"source_name": "mitre-attack", "external_id": ext_id}], **extra}
    if aliases:
        obj[alias_field] = [name, *aliases]
    return obj


BUNDLE = {"objects": [
    stix("intrusion-set", "APT28", "G0007", ["Fancy Bear", "Sofacy"]),
    stix("malware", "X-Agent", "S0161", ["CHOPSTICK"], alias_field="x_mitre_aliases"),
    stix("malware", "Sofacy", "S9999"),  # also a group alias -> ambiguous
    stix("tool", "Mimikatz", "S0002"),
    stix("tool", "at", "S0110"),
    stix("attack-pattern", "Spearphishing Attachment", "T1566.001"),
    stix("attack-pattern", "Masquerading", "T1036"),
    stix("malware", "OldThing", "S0001", revoked=True),
    stix("tool", "Gone", "S0003", x_mitre_deprecated=True),
    {"type": "course-of-action", "name": "Audit"},
]}


def names(entries):
    return {(e["name"], e["type"]) for e in entries}


def test_attack_entries_reads_names_aliases_and_ids():
    entries = attack_entries(BUNDLE)
    assert ("Fancy Bear", "ThreatGroup") in names(entries)
    assert ("CHOPSTICK", "Malware") in names(entries)
    assert ("Mimikatz", "Tool") in names(entries)
    assert ("Spearphishing Attachment", "AttackTechnique") in names(entries)
    assert {e["id"] for e in entries if e["name"] == "Fancy Bear"} == {"G0007"}


def test_attack_entries_skip_revoked_and_deprecated():
    assert not {"OldThing", "Gone", "Audit"} & {e["name"] for e in attack_entries(BUNDLE)}


def test_clean_drops_names_with_two_types():
    kept, dropped = clean_entries(attack_entries(BUNDLE))
    assert "Sofacy" not in {e["name"] for e in kept}
    assert any(d["name"] == "Sofacy" and "ambiguous" in d["reason"] for d in dropped)


def test_clean_drops_short_generic_names_but_keeps_distinctive_caps():
    entries = [{"name": n, "type": "Tool", "id": "S1"} for n in ["at", "Net", "DNS", "WCE"]]
    kept, _ = clean_entries(entries)
    assert {e["name"] for e in kept} == {"WCE"}


def test_clean_drops_single_word_techniques_and_stoplisted_names():
    entries = [{"name": "Masquerading", "type": "AttackTechnique", "id": "T1036"},
               {"name": "Page", "type": "Malware", "id": "S1"},
               {"name": "PlugX", "type": "Malware", "id": "S2"}]
    kept, _ = clean_entries(entries)
    assert {e["name"] for e in kept} == {"PlugX"}


def test_clean_sets_case_sensitivity():
    kept, _ = clean_entries(attack_entries(BUNDLE))
    by_name = {e["name"]: e for e in kept}
    assert by_name["APT28"]["case_sensitive"] is True
    assert by_name["Spearphishing Attachment"]["case_sensitive"] is False


def test_location_entries_use_names_demonyms_and_regions():
    countries = [
        {"cca2": "RU", "name": {"common": "Russia", "official": "Russian Federation"},
         "altSpellings": ["RU", "Rossiya"], "demonyms": {"eng": {"m": "Russian", "f": "Russian"}}},
        {"cca2": "US", "name": {"common": "United States", "official": "United States of America"},
         "altSpellings": ["US", "USA"], "demonyms": {"eng": {"m": "American", "f": "American"}}},
    ]
    entries = location_entries(countries, regions=["Middle East"])
    got = {e["name"] for e in entries}
    assert {"Russia", "Russian Federation", "Rossiya", "Russian", "United States", "USA", "US",
            "American", "Middle East"} <= got
    assert "RU" not in got  # two-letter codes are too ambiguous, except whitelisted ones
    assert all(e["type"] == "Location" and e["case_sensitive"] for e in entries)


def technique(name, ext_id, tactics, sub=True):
    return stix("attack-pattern", name, ext_id, x_mitre_is_subtechnique=sub,
                kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics])


def test_drops_recon_and_resource_development_sub_techniques():
    bundle = {"objects": [
        technique("Email Addresses", "T1589.002", ["reconnaissance"]),
        technique("Virtual Private Server", "T1583.003", ["resource-development"]),
        technique("Gather Victim Identity Information", "T1589", ["reconnaissance"], sub=False),
        technique("Web Shell", "T1505.003", ["persistence"]),
    ]}
    kept, dropped = clean_entries(attack_entries(bundle))
    assert {e["name"] for e in kept} == {"Gather Victim Identity Information", "Web Shell"}
    assert {d["name"] for d in dropped if "target or resource" in d["reason"]} == {
        "Email Addresses", "Virtual Private Server"}


def test_drops_generic_technique_names():
    bundle = {"objects": [technique("Visual Basic", "T1059.005", ["execution"]),
                          technique("Malicious File", "T1204.002", ["execution"])]}
    kept, _ = clean_entries(attack_entries(bundle))
    assert kept == []


def test_equation_group_replaces_bare_equation():
    bundle = {"objects": [stix("intrusion-set", "Equation", "G0020")]}
    kept, _ = clean_entries(attack_entries(bundle))
    assert {e["name"] for e in kept} == {"Equation Group"}

from crawler.extraction.rules import RuleMatcher, load_matcher

ENTRIES = [
    {"name": "APT28", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
    {"name": "Fancy Bear", "type": "ThreatGroup", "id": "G0007", "case_sensitive": True},
    {"name": "Bear", "type": "ThreatGroup", "id": "G9999", "case_sensitive": True},
    {"name": "Lazarus Group", "type": "ThreatGroup", "id": "G0032", "case_sensitive": True},
    {"name": "X-Agent", "type": "Malware", "id": "S0161", "case_sensitive": True},
    {"name": "Mimikatz", "type": "Tool", "id": "S0002", "case_sensitive": True},
    {
        "name": "Spearphishing Attachment",
        "type": "AttackTechnique",
        "id": "T1566.001",
        "case_sensitive": False,
    },
    {"name": "Germany", "type": "Location", "id": "DE", "case_sensitive": True},
    {"name": "People's Republic of China", "type": "Location", "id": "CN", "case_sensitive": True},
]


def found(text, types=None):
    spans, _ = RuleMatcher(ENTRIES).find(text, types)
    return [(s[2], s[3]) for s in spans]


def test_finds_dictionary_names_with_positions():
    spans, _ = RuleMatcher(ENTRIES).find("APT28 used X-Agent in Germany .")
    assert spans == [
        [0, 1, "APT28", "ThreatGroup"],
        [2, 3, "X-Agent", "Malware"],
        [4, 5, "Germany", "Location"],
    ]


def test_longest_match_wins():
    assert found("also known as Fancy Bear .") == [("Fancy Bear", "ThreatGroup")]


def test_dictionary_is_case_sensitive_for_names():
    assert found("the apt28 and mimikatz strings") == []


def test_techniques_match_case_insensitively():
    assert found("sent a spearphishing attachment") == [
        ("spearphishing attachment", "AttackTechnique")
    ]


def test_multi_token_names_use_tokenizer_form():
    assert found("the People 's Republic of China .") == [
        ("People 's Republic of China", "Location")
    ]


def test_finds_regex_indicators_and_times():
    text = "In March 2019 , X-Agent contacted evil[.]com and dropped a.exe ( CVE-2017-11882 , T1566.001 ) ."
    assert found(text) == [
        ("March 2019", "Time"),
        ("X-Agent", "Malware"),
        ("evil[.]com", "NetworkInfra"),
        ("a.exe", "FileHash"),
        ("CVE-2017-11882", "Vulnerability"),
        ("T1566.001", "AttackTechnique"),
    ]


def test_regex_wins_over_dictionary_on_overlap():
    entries = ENTRIES + [
        {"name": "evil[.]com", "type": "Malware", "id": "S1", "case_sensitive": True}
    ]
    spans, _ = RuleMatcher(entries).find("it contacted evil[.]com")
    assert [(s[2], s[3]) for s in spans] == [("evil[.]com", "NetworkInfra")]


def test_only_selected_types_are_found():
    text = "In 2019 APT28 used X-Agent against Germany ."
    assert found(text, types={"Malware", "Location"}) == [
        ("X-Agent", "Malware"),
        ("Germany", "Location"),
    ]
    assert found(text, types=set()) == []


def test_repeated_mentions_are_all_found():
    assert found("X-Agent and X-Agent") == [("X-Agent", "Malware"), ("X-Agent", "Malware")]


def test_aliases_of_one_group_are_linked():
    spans, triples = RuleMatcher(ENTRIES).find("APT28 , also known as Fancy Bear , used X-Agent .")
    assert [s[2] for s in spans] == ["APT28", "Fancy Bear", "X-Agent"]
    assert triples == [(0, "alias-of", 1)]


def test_different_groups_and_repeats_are_not_aliases():
    _, triples = RuleMatcher(ENTRIES).find("APT28 and Lazarus Group , then APT28 again")
    assert triples == []


def test_shipped_dictionary_and_patterns_only_use_ontology_types(ontology):
    matcher = load_matcher()
    dictionary_types = {t for t, _ in [*matcher.exact.values(), *matcher.folded.values()]}
    pattern_types = {"NetworkInfra", "FileHash", "Vulnerability", "AttackTechnique", "Time"}

    assert dictionary_types | pattern_types <= set(ontology.entity_names)

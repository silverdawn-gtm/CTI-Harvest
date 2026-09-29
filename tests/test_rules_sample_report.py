"""End-to-end check of the rule stage on a sample report, using the real dictionaries."""
import pytest

from extractors.rules import DICTIONARY_PATH, load_matcher
from tokenizer import split_sentences, tokenize

pytestmark = pytest.mark.skipif(not DICTIONARY_PATH.exists(), reason="run build_dictionaries.py first")

REPORT = """
In March 2019, APT28 (also known as Fancy Bear) sent spearphishing attachments to government agencies in Germany.
The lure, Invoice_2019.docm, exploited CVE-2017-11882 and dropped X-Agent, which contacted hxxp://update-check[.]com/gate.php and 185.12.45[.]6:443.
The dropper's SHA256 was 3f1b6a2d9c8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a.
Operators used Mimikatz for credential dumping (T1003.001) and Cobalt Strike for lateral movement.
On 12 June 2020, Lazarus Group targeted banks in South Korea using a web shell hosted at evil[.]ru.
"""

EXPECTED = {
    ("March 2019", "Time"), ("APT28", "ThreatGroup"), ("Fancy Bear", "ThreatGroup"),
    ("spearphishing attachments", None),  # plural is not the ATT&CK name; left for the LLM
    ("Germany", "Location"), ("Invoice_2019.docm", "FileHash"), ("CVE-2017-11882", "Vulnerability"),
    ("X-Agent", "Malware"), ("hxxp://update-check[.]com/gate.php", "NetworkInfra"),
    ("185.12.45[.]6:443", "NetworkInfra"),
    ("3f1b6a2d9c8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a", "FileHash"),
    ("Mimikatz", "Tool"), ("T1003.001", "AttackTechnique"), ("Cobalt Strike", "Malware"),
    ("12 June 2020", "Time"), ("Lazarus Group", "ThreatGroup"), ("South Korea", "Location"),
    ("web shell", "AttackTechnique"), ("evil[.]ru", "NetworkInfra"),
}


@pytest.fixture(scope="module")
def found():
    matcher = load_matcher()
    out, aliases = set(), []
    for sentence in split_sentences(REPORT.strip()):
        spans, triples = matcher.find(tokenize(sentence))
        out |= {(s[2], s[3]) for s in spans}
        aliases += [(spans[j][2], spans[i][2]) for j, _, i in triples]
    return out, aliases


@pytest.mark.parametrize("surface,type_", sorted(EXPECTED, key=str))
def test_sample_report_entity(found, surface, type_):
    types = {t for s, t in found[0] if s == surface}
    assert types == ({type_} if type_ else set())


def test_sample_report_has_no_unexpected_entities(found):
    assert {s for s, _ in found[0]} <= {s for s, _ in EXPECTED}


def test_sample_report_links_the_aliases(found):
    assert found[1] == [("APT28", "Fancy Bear")]

import pytest

from extractors.patterns import find_times, match_token

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"


@pytest.mark.parametrize("token", [
    "hxxp://evil[.]com/a.php", "https://example.com", "hXXps://x[.]ru/p?q=1", "http://1.2.3.4:8080/x",
    "185.12.45.6", "185.12.45[.]6", "10.0.0.1:443", "185[.]12[.]45[.]6",
    "evil[.]com", "update.microsoft-cdn.net", "evil(.)ru", "evil[dot]com", "mail.gov.ua",
])
def test_network_infrastructure(token):
    assert match_token(token) == "NetworkInfra"


@pytest.mark.parametrize("token", [MD5, SHA1, SHA256, "invoice.doc", "payload.EXE", "report.pdf",
                                   "version.dll", "update.ps1", "Invoice_2019.docm"])
def test_file_or_hash(token):
    assert match_token(token) == "FileHash"


@pytest.mark.parametrize("token", ["CVE-2017-11882", "cve-2017-0199", "CVE-2021-44228", "MS17-010"])
def test_vulnerability(token):
    assert match_token(token) == "Vulnerability"


@pytest.mark.parametrize("token", ["T1566", "T1566.001", "T1059.003"])
def test_attack_technique_id(token):
    assert match_token(token) == "AttackTechnique"


@pytest.mark.parametrize("token", [
    "Node.js", "ASP.NET", "U.S.", "e.g.", "3.5", "999.1.1.1", "1.2.3", "a.b", "T15", "TA0001",
    "APT28", "admin@338", "CVE", "the", "2019", "x" * 32, "v2.0",
])
def test_non_matches(token):
    assert match_token(token) is None


def spans(text):
    tokens = text.split()
    return [" ".join(tokens[s:e]) for s, e in find_times(tokens)]


@pytest.mark.parametrize("text,expected", [
    ("in March 2019 .", ["March 2019"]),
    ("on 12 March 2019 they", ["12 March 2019"]),
    ("March 12 , 2019 was", ["March 12 , 2019"]),
    ("since 2017 , and in 2018", ["2017", "2018"]),
    ("in May 2018", ["May 2018"]),
    ("in January the group", ["January"]),
    ("on Jan. 5 , 2020", ["Jan. 5 , 2020"]),
    ("on 2019-03-12 and 12/03/2019", ["2019-03-12", "12/03/2019"]),
    ("between 2016-2018", ["2016-2018"]),
])
def test_find_times(text, expected):
    assert spans(text) == expected


@pytest.mark.parametrize("text", [
    "it may be", "May the group", "Windows Server 2008 is old", "on port 2000", "Office 2016 docs",
    "version 2019", "1234 files",
])
def test_find_times_ignores_non_dates(text):
    assert spans(text) == []

import json
from datetime import datetime, timezone
from pathlib import Path

from crawler.core.models import DiscoveredItem, RawDocument
from crawler.sources.kev import KevSource

FIXTURE = Path(__file__).parent.parent / "fixtures" / "kev" / "catalog.json"


def make_raw() -> RawDocument:
    return RawDocument(
        item=DiscoveredItem(url=KevSource.CATALOG_URL, source="kev"),
        content=FIXTURE.read_bytes(),
        content_type="application/json",
        http_status=200,
        fetched_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )


async def test_discover_yields_the_catalog_url():
    since = datetime(2020, 1, 1, tzinfo=timezone.utc)
    items = [item async for item in KevSource().discover(since=since)]

    assert len(items) == 1
    assert items[0].url == KevSource.CATALOG_URL


def test_parse_returns_one_doc_per_vulnerability():
    docs = KevSource().parse(make_raw()).documents

    assert len(docs) == 2
    assert {d.title for d in docs} == {
        "Microsoft Windows SmartScreen Security Feature Bypass Vulnerability",
        "Citrix NetScaler Sensitive Information Disclosure Vulnerability",
    }


def test_each_doc_gets_a_unique_url():
    docs = KevSource().parse(make_raw()).documents

    assert docs[0].url.endswith("#CVE-2024-21412")
    assert len({d.url_hash for d in docs}) == 2


def test_parse_emits_vulnerability_facts_with_kev_flags():
    fact = KevSource().parse(make_raw()).vulnerabilities[0]

    assert fact.cve_id == "CVE-2024-21412"
    assert fact.vendor == "Microsoft"
    assert fact.product == "Windows SmartScreen"
    assert fact.kev_listed is True
    assert fact.kev_added_date == datetime(2024, 2, 13, tzinfo=timezone.utc)


def test_body_text_includes_description_and_required_action():
    docs = KevSource().parse(make_raw()).documents

    assert "bypass SmartScreen protections" in docs[0].body_text
    assert "Apply mitigations" in docs[0].body_text


def test_malformed_entry_is_skipped_with_a_warning():
    payload = json.loads(FIXTURE.read_text())
    payload["vulnerabilities"].append({"vendorProject": "NoCve"})  # missing cveID
    raw = RawDocument(
        item=DiscoveredItem(url=KevSource.CATALOG_URL, source="kev"),
        content=json.dumps(payload).encode(),
        content_type="application/json",
        http_status=200,
        fetched_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )

    docs = KevSource().parse(raw).documents

    assert len(docs) == 2  # the malformed entry produced no document

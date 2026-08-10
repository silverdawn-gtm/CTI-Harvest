from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import select

from crawler.core.archive import RawArchive
from crawler.core.fetch import Fetcher
from crawler.core.pipeline import run_source
from crawler.core.ratelimit import DomainRateLimiter
from crawler.db.schema import Document, Vulnerability
from crawler.sources.base import RateLimit
from crawler.sources.kev import KevSource

FIXTURE = Path(__file__).parent / "fixtures" / "kev" / "catalog.json"


async def test_kev_flows_from_http_to_database(db_session, tmp_path):
    def handler(request):
        assert request.url.path.endswith("known_exploited_vulnerabilities.json")
        return httpx.Response(
            200, content=FIXTURE.read_bytes(), headers={"content-type": "application/json"}
        )

    async def no_sleep(seconds):
        return None

    fetcher = Fetcher(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limiter=DomainRateLimiter(RateLimit(requests=10, per_seconds=1.0), sleep=no_sleep),
        user_agent="test-agent",
        sleep=no_sleep,
    )

    run = await run_source(
        KevSource(),
        fetcher,
        RawArchive(tmp_path),
        db_session,
        since=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )

    assert run.status == "ok"
    assert run.parsed == 2

    docs = db_session.execute(select(Document).where(Document.source == "kev")).scalars().all()
    assert len(docs) == 2
    assert all(d.raw_path.startswith("kev/") for d in docs)
    assert all(d.body_text for d in docs)

    kev_vuln = db_session.get(Vulnerability, "CVE-2024-21412")
    assert kev_vuln.kev_listed is True
    assert kev_vuln.vendor == "Microsoft"


async def test_rerunning_is_idempotent(db_session, tmp_path):
    def handler(request):
        return httpx.Response(
            200, content=FIXTURE.read_bytes(), headers={"content-type": "application/json"}
        )

    async def no_sleep(seconds):
        return None

    def build():
        return Fetcher(
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            limiter=DomainRateLimiter(RateLimit(requests=10, per_seconds=1.0), sleep=no_sleep),
            user_agent="test-agent",
            sleep=no_sleep,
        )

    since = datetime(2020, 1, 1, tzinfo=timezone.utc)
    await run_source(KevSource(), build(), RawArchive(tmp_path), db_session, since=since)
    db_session.flush()
    second = await run_source(KevSource(), build(), RawArchive(tmp_path), db_session, since=since)

    # Content is byte-identical, so the second run stores nothing new.
    assert second.parsed == 0
    docs = db_session.execute(select(Document).where(Document.source == "kev")).scalars().all()
    assert len(docs) == 2

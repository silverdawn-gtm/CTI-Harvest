from datetime import datetime, timezone

from crawler.core.fetch import PermanentFetchError
from crawler.core.models import DiscoveredItem, ParsedDoc, RawDocument
from crawler.core.pipeline import run_source
from crawler.db import repo
from crawler.sources.base import RateLimit

NOW = datetime(2026, 3, 15, tzinfo=timezone.utc)


class StubSource:
    name = "stub"
    kind = "api"
    license = "public-domain"
    rate_limit = RateLimit(requests=100, per_seconds=1.0)

    def __init__(self, urls):
        self._urls = urls

    async def discover(self, since):
        for url in self._urls:
            yield DiscoveredItem(url=url, source=self.name)

    def parse(self, raw):
        return [
            ParsedDoc(
                url=raw.item.url,
                source=self.name,
                title=f"Doc {raw.item.url}",
                body_text=raw.content.decode(),
                license=self.license,
            )
        ]


class StubFetcher:
    """Returns a canned result per URL: bytes, an exception, or None for 304."""

    def __init__(self, results):
        self._results = results
        self.conditional_headers = []

    async def fetch(self, item, etag=None, last_modified=None):
        self.conditional_headers.append((item.url, etag, last_modified))
        result = self._results[item.url]
        if isinstance(result, Exception):
            raise result
        if result is None:
            return None
        return RawDocument(
            item=item,
            content=result,
            content_type="application/json",
            http_status=200,
            fetched_at=NOW,
            etag='W/"v1"',
        )


class StubArchive:
    def __init__(self):
        self.stored = []

    def store(self, raw):
        self.stored.append(raw.item.url)
        return f"stub/{raw.item.url_hash}.json.gz"


async def test_happy_path_persists_documents(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    source = StubSource(["https://example.org/1", "https://example.org/2"])
    fetcher = StubFetcher({"https://example.org/1": b"one", "https://example.org/2": b"two"})
    archive = StubArchive()

    run = await run_source(source, fetcher, archive, db_session, since=NOW)

    assert run.discovered == 2
    assert run.fetched == 2
    assert run.parsed == 2
    assert run.failed == 0
    assert run.status == "ok"
    assert archive.stored == ["https://example.org/1", "https://example.org/2"]


async def test_unchanged_document_sends_conditional_headers_and_is_skipped(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    url = "https://example.org/1"

    first_source = StubSource([url])
    first_fetcher = StubFetcher({url: b"one"})
    await run_source(first_source, first_fetcher, StubArchive(), db_session, since=NOW)
    db_session.flush()

    second_fetcher = StubFetcher({url: None})  # server answers 304
    run = await run_source(StubSource([url]), second_fetcher, StubArchive(), db_session, since=NOW)

    assert second_fetcher.conditional_headers == [(url, 'W/"v1"', None)]
    assert run.fetched == 0
    assert run.parsed == 0
    assert run.status == "ok"


async def test_permanent_error_is_recorded_and_run_continues(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    source = StubSource(["https://example.org/gone", "https://example.org/ok"])
    fetcher = StubFetcher(
        {
            "https://example.org/gone": PermanentFetchError("404"),
            "https://example.org/ok": b"fine",
        }
    )

    run = await run_source(source, fetcher, StubArchive(), db_session, since=NOW)

    assert run.failed == 1
    assert run.parsed == 1
    assert run.status == "ok"


async def test_circuit_breaker_opens_after_five_consecutive_failures(db_session):
    repo.ensure_source(db_session, "stub", "api", "public-domain")
    urls = [f"https://example.org/{i}" for i in range(10)]
    source = StubSource(urls)
    fetcher = StubFetcher({url: PermanentFetchError("404") for url in urls})

    run = await run_source(source, fetcher, StubArchive(), db_session, since=NOW)

    assert run.status == "circuit_open"
    assert run.failed == 5
    assert len(fetcher.conditional_headers) == 5  # stopped early

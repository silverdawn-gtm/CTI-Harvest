import httpx
import pytest

from crawler.core.fetch import (
    Fetcher,
    PermanentFetchError,
    RobotsCache,
    RobotsDisallowed,
    TransientFetchError,
)
from crawler.core.models import DiscoveredItem
from crawler.core.ratelimit import DomainRateLimiter
from crawler.sources.base import RateLimit

ITEM = DiscoveredItem(url="https://example.org/a", source="test")


def make_fetcher(handler, slept: list[float]):
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = DomainRateLimiter(
        default=RateLimit(requests=100, per_seconds=1.0), sleep=fake_sleep
    )
    return Fetcher(client=client, limiter=limiter, user_agent="test-agent", sleep=fake_sleep)


async def test_successful_fetch_returns_raw_document():
    def handler(request):
        assert request.headers["user-agent"] == "test-agent"
        return httpx.Response(200, content=b'{"ok": true}',
                              headers={"content-type": "application/json", "etag": "W/\"v1\""})

    raw = await make_fetcher(handler, []).fetch(ITEM)

    assert raw is not None
    assert raw.content == b'{"ok": true}'
    assert raw.etag == 'W/"v1"'
    assert raw.http_status == 200


async def test_304_returns_none_and_sends_conditional_headers():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(304)

    raw = await make_fetcher(handler, []).fetch(
        ITEM, etag='W/"v1"', last_modified="Mon, 01 Jan 2024 00:00:00 GMT"
    )

    assert raw is None
    assert seen["if-none-match"] == 'W/"v1"'
    assert seen["if-modified-since"] == "Mon, 01 Jan 2024 00:00:00 GMT"


async def test_404_raises_permanent_without_retrying():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(404)

    with pytest.raises(PermanentFetchError):
        await make_fetcher(handler, []).fetch(ITEM)

    assert len(calls) == 1


async def test_429_retries_with_backoff_then_succeeds():
    calls = []
    slept: list[float] = []

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(429, headers={"retry-after": "7"})
        return httpx.Response(200, content=b"ok", headers={"content-type": "text/plain"})

    raw = await make_fetcher(handler, slept).fetch(ITEM)

    assert raw is not None
    assert len(calls) == 3
    assert slept[:2] == [7.0, 7.0]  # Retry-After honoured over computed backoff


async def test_persistent_500_raises_transient_after_max_attempts():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(500)

    with pytest.raises(TransientFetchError):
        await make_fetcher(handler, []).fetch(ITEM)

    assert len(calls) == 4


ROBOTS = b"""
User-agent: *
Disallow: /private/
"""


def robots_handler(fetched: list[str]):
    def handler(request):
        if request.url.path == "/robots.txt":
            fetched.append(str(request.url))
            return httpx.Response(200, content=ROBOTS, headers={"content-type": "text/plain"})
        return httpx.Response(200, content=b"page", headers={"content-type": "text/html"})

    return handler


async def test_robots_allows_permitted_path():
    client = httpx.AsyncClient(transport=httpx.MockTransport(robots_handler([])))
    robots = RobotsCache(client=client, user_agent="test-agent")

    assert await robots.allowed("https://example.org/public/a") is True


async def test_robots_blocks_disallowed_path():
    client = httpx.AsyncClient(transport=httpx.MockTransport(robots_handler([])))
    robots = RobotsCache(client=client, user_agent="test-agent")

    assert await robots.allowed("https://example.org/private/secret") is False


async def test_robots_is_fetched_once_per_host():
    fetched: list[str] = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(robots_handler(fetched)))
    robots = RobotsCache(client=client, user_agent="test-agent")

    await robots.allowed("https://example.org/a")
    await robots.allowed("https://example.org/b")

    assert len(fetched) == 1


async def test_missing_robots_allows_everything():
    def handler(request):
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(200, content=b"page")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    robots = RobotsCache(client=client, user_agent="test-agent")

    assert await robots.allowed("https://example.org/anything") is True


async def test_fetcher_raises_when_robots_disallows():
    fetcher = make_fetcher(robots_handler([]), [])
    fetcher.robots = RobotsCache(
        client=httpx.AsyncClient(transport=httpx.MockTransport(robots_handler([]))),
        user_agent="test-agent",
    )

    with pytest.raises(RobotsDisallowed):
        await fetcher.fetch(DiscoveredItem(url="https://example.org/private/x", source="test"))

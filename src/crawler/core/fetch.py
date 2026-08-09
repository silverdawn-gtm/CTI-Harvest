import asyncio
import random
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

from crawler.core.models import DiscoveredItem, RawDocument
from crawler.core.ratelimit import DomainRateLimiter

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
PERMANENT_STATUS = {400, 401, 403, 404, 410}


class FetchError(Exception):
    pass


class PermanentFetchError(FetchError):
    """Do not retry: the resource is gone or forbidden."""


class TransientFetchError(FetchError):
    """Retries were exhausted; the URL may succeed later."""


class RobotsDisallowed(FetchError):
    """The site's robots.txt forbids fetching this URL."""


class RobotsCache:
    """Fetches and caches robots.txt per host. A missing file means everything is allowed."""

    def __init__(self, client: httpx.AsyncClient, user_agent: str) -> None:
        self._client = client
        self._user_agent = user_agent
        self._parsers: dict[str, RobotFileParser | None] = {}

    async def allowed(self, url: str) -> bool:
        parts = urlparse(url)
        host = parts.netloc
        if host not in self._parsers:
            self._parsers[host] = await self._load(f"{parts.scheme}://{host}/robots.txt")
        parser = self._parsers[host]
        if parser is None:
            return True
        return parser.can_fetch(self._user_agent, url)

    async def _load(self, robots_url: str) -> RobotFileParser | None:
        try:
            response = await self._client.get(
                robots_url, headers={"user-agent": self._user_agent}
            )
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser


class Fetcher:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: DomainRateLimiter,
        user_agent: str,
        max_attempts: int = 4,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        robots: RobotsCache | None = None,
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._user_agent = user_agent
        self._max_attempts = max_attempts
        self._sleep = sleep or asyncio.sleep
        self.robots = robots

    async def fetch(
        self,
        item: DiscoveredItem,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> RawDocument | None:
        if self.robots is not None and not await self.robots.allowed(item.url):
            raise RobotsDisallowed(f"robots.txt forbids {item.url}")

        headers = {"user-agent": self._user_agent}
        if etag:
            headers["if-none-match"] = etag
        if last_modified:
            headers["if-modified-since"] = last_modified

        last_error: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            await self._limiter.acquire(item.url)
            try:
                response = await self._client.get(
                    item.url, headers=headers, follow_redirects=True
                )
            except httpx.HTTPError as exc:
                last_error = exc
                await self._backoff(attempt, None)
                continue

            if response.status_code == 304:
                return None

            if response.status_code in PERMANENT_STATUS:
                raise PermanentFetchError(f"{response.status_code} for {item.url}")

            if response.status_code in RETRYABLE_STATUS:
                last_error = TransientFetchError(f"{response.status_code} for {item.url}")
                if attempt < self._max_attempts:
                    await self._backoff(attempt, response.headers.get("retry-after"))
                continue

            response.raise_for_status()
            return RawDocument(
                item=item,
                content=response.content,
                content_type=response.headers.get("content-type", ""),
                http_status=response.status_code,
                fetched_at=datetime.now(timezone.utc),
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
            )

        raise TransientFetchError(
            f"gave up on {item.url} after {self._max_attempts} attempts"
        ) from last_error

    async def _backoff(self, attempt: int, retry_after: str | None) -> None:
        """Honour Retry-After when present, otherwise exponential backoff with jitter."""
        if retry_after:
            try:
                await self._sleep(float(retry_after))
                return
            except ValueError:
                pass  # Retry-After may be an HTTP date; fall through to backoff
        await self._sleep(min(60.0, 2**attempt) + random.uniform(0, 0.5))

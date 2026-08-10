import asyncio
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from crawler.core.models import RateLimit


class DomainRateLimiter:
    """Enforces `requests per per_seconds` independently for each host."""

    def __init__(
        self,
        default: RateLimit,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._default = default
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._limits: dict[str, RateLimit] = {}
        self._recent: dict[str, list[float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def set_limit(self, host: str, limit: RateLimit) -> None:
        self._limits[host] = limit

    async def acquire(self, url: str) -> None:
        host = urlparse(url).netloc
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            limit = self._limits.get(host, self._default)
            window = self._recent.setdefault(host, [])
            now = self._clock()

            cutoff = now - limit.per_seconds
            window[:] = [t for t in window if t > cutoff]

            if len(window) >= limit.requests:
                wait = window[0] + limit.per_seconds - now
                if wait > 0:
                    await self._sleep(wait)
                    now = self._clock()
                    cutoff = now - limit.per_seconds
                    window[:] = [t for t in window if t > cutoff]

            window.append(now)

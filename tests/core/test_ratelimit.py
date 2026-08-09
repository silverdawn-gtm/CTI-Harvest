from crawler.core.ratelimit import DomainRateLimiter
from crawler.sources.base import RateLimit


class FakeClock:
    """Deterministic clock: sleeping advances time instead of waiting."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


async def test_second_request_to_same_host_waits():
    clock = FakeClock()
    limiter = DomainRateLimiter(
        default=RateLimit(requests=1, per_seconds=2.0), clock=clock.time, sleep=clock.sleep
    )

    await limiter.acquire("https://example.org/a")
    await limiter.acquire("https://example.org/b")

    assert clock.slept == [2.0]


async def test_different_hosts_do_not_block_each_other():
    clock = FakeClock()
    limiter = DomainRateLimiter(
        default=RateLimit(requests=1, per_seconds=2.0), clock=clock.time, sleep=clock.sleep
    )

    await limiter.acquire("https://a.example/x")
    await limiter.acquire("https://b.example/y")

    assert clock.slept == []


async def test_per_host_override_is_used():
    clock = FakeClock()
    limiter = DomainRateLimiter(
        default=RateLimit(requests=1, per_seconds=1.0), clock=clock.time, sleep=clock.sleep
    )
    limiter.set_limit("slow.example", RateLimit(requests=1, per_seconds=6.0))

    await limiter.acquire("https://slow.example/a")
    await limiter.acquire("https://slow.example/b")

    assert clock.slept == [6.0]

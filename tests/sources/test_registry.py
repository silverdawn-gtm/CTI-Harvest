import pytest

from crawler.sources.base import RateLimit, all_sources, get_source, register


class _Fake:
    name = "fake"
    kind = "api"
    license = "public-domain"
    rate_limit = RateLimit(requests=1, per_seconds=1.0)

    async def discover(self, since, fetcher=None):
        yield None

    def parse(self, raw):
        return []


def test_register_and_retrieve():
    source = _Fake()
    register(source)

    assert get_source("fake") is source
    assert source in all_sources()


def test_unknown_source_raises():
    with pytest.raises(KeyError, match="unknown"):
        get_source("unknown")

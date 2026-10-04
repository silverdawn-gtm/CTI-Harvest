import asyncio
import json

import httpx
import pytest

from crawler.config import Settings
from crawler.extraction.client import PROVIDERS, ChatClient, LLMError, build_chat_client

URL = "https://llm.example/v1/chat/completions"


class RecordingLimiter:
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def acquire(self, url: str) -> None:
        self.urls.append(url)


def ok(content: str = '{"entities": [], "relations": []}') -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def make(handler, models=("m1",), gate=None, limiter=None, sleeps=None) -> ChatClient:
    async def sleep(seconds: float) -> None:
        if sleeps is not None:
            sleeps.append(seconds)

    return ChatClient(
        URL,
        "secret",
        list(models),
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limiter or RecordingLimiter(),
        gate or asyncio.Semaphore(4),
        sleep=sleep,
    )


async def test_sends_a_strict_json_schema_and_returns_the_content():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return ok("REPLY")

    chat = make(handler)
    assert await chat("the prompt", {"type": "object"}) == "REPLY"

    body = json.loads(seen[0].content)
    assert body["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "cti_extraction", "schema": {"type": "object"}, "strict": True},
    }
    assert body["model"] == "m1" and body["temperature"] == 0
    assert body["messages"] == [{"role": "user", "content": "the prompt"}]
    assert seen[0].headers["authorization"] == "Bearer secret"
    assert chat.last_model == "m1"


async def test_every_attempt_passes_the_rate_limiter():
    replies = iter([httpx.Response(429), ok()])
    limiter = RecordingLimiter()
    chat = make(lambda request: next(replies), limiter=limiter)

    await chat("p", {})

    assert limiter.urls == [URL, URL]


async def test_rate_limits_and_server_errors_are_retried_with_backoff():
    replies = iter([httpx.Response(429), httpx.Response(503), ok("fine")])
    sleeps: list[float] = []
    chat = make(lambda request: next(replies), sleeps=sleeps)

    assert await chat("p", {}) == "fine"
    assert sleeps == [2, 4]


async def test_client_errors_are_not_retried():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(400, text="schema not supported")

    with pytest.raises(LLMError, match="HTTP 400: schema not supported"):
        await make(handler)("p", {})
    assert len(calls) == 1


async def test_model_without_allowance_falls_back_to_the_next():
    def handler(request):
        if json.loads(request.content)["model"] == "m1":
            return httpx.Response(429, headers={"x-ratelimit-limit-req-minute": "0"})
        return ok("from m2")

    chat = make(handler, models=("m1", "m2"))

    assert await chat("p", {}) == "from m2"
    assert chat.last_model == "m2"


async def test_gives_up_after_the_retries():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503)

    with pytest.raises(LLMError, match="HTTP 503"):
        await make(handler)("p", {})
    assert len(calls) == 3


async def test_network_errors_are_retried_then_reported():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(LLMError, match="ConnectError"):
        await make(handler)("p", {})


async def test_unexpected_response_shape_is_an_llm_error():
    with pytest.raises(LLMError, match="unexpected response shape"):
        await make(lambda request: httpx.Response(200, json={"oops": 1}))("p", {})


async def test_the_semaphore_bounds_requests_in_flight():
    in_flight = peak = 0

    async def handler(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return ok()

    chat = make(handler, gate=asyncio.Semaphore(2))
    await asyncio.gather(*(chat("p", {}) for _ in range(6)))

    assert peak == 2


def settings(**values) -> Settings:
    return Settings(_env_file=None, database_url="postgresql+psycopg://x@y/z", **values)


def test_build_chat_client_needs_the_providers_key():
    with pytest.raises(LLMError, match="GROK_API_KEY"):
        build_chat_client(
            settings(llm_provider="grok", grok_api_key=None),
            httpx.AsyncClient(),
            RecordingLimiter(),
            asyncio.Semaphore(1),
        )


def test_build_chat_client_uses_the_provider_url_and_fallbacks():
    chat = build_chat_client(
        settings(
            llm_provider="gemini",
            gemini_api_key="k",
            gemini_model="a",
            gemini_fallback_models="b, c,",
        ),
        httpx.AsyncClient(),
        RecordingLimiter(),
        asyncio.Semaphore(1),
    )
    assert chat.url == PROVIDERS["gemini"]
    assert chat.models == ["a", "b", "c"]

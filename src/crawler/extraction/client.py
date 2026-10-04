"""Async client for OpenAI-compatible chat-completion APIs with structured outputs.

Mistral, Gemini (through its OpenAI compatibility endpoint) and xAI Grok all accept a strict
`json_schema` response format, so one client serves all three. Every request waits on a
shared semaphore and then on a DomainRateLimiter: the same controls that keep the crawler
polite to publishers keep extraction inside API quotas.
"""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Protocol

import httpx

from crawler.config import Settings

PROVIDERS: dict[str, str] = {
    "mistral": "https://api.mistral.ai/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "grok": "https://api.x.ai/v1/chat/completions",
}
RETRY_STATUS = frozenset({429, 500, 502, 503})
SCHEMA_NAME = "cti_extraction"


class LLMError(RuntimeError):
    """The provider did not produce a usable reply."""


class Limiter(Protocol):
    async def acquire(self, url: str) -> None: ...


def response_format(schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {"name": SCHEMA_NAME, "schema": schema, "strict": True},
    }


class ChatClient:
    """complete(prompt, schema) for one provider, trying each model in order.

    429 and 5xx are retried with backoff; any other error status is raised at once, since
    retrying a rejected key or schema only spends quota. A model the account has no
    allowance for (limit 0 requests/minute) is skipped for the rest of the run.
    `last_model` names the model that answered most recently.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        models: Sequence[str],
        client: httpx.AsyncClient,
        limiter: Limiter,
        gate: asyncio.Semaphore,
        retries: int = 2,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        if not models:
            raise ValueError("at least one model is required")
        self.url = url
        self.models = list(models)
        self.last_model: str | None = None
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._client = client
        self._limiter = limiter
        self._gate = gate
        self._retries = retries
        self._sleep = sleep or asyncio.sleep
        self._unavailable: set[str] = set()

    async def __call__(self, prompt: str, schema: dict[str, Any]) -> str:
        last_error: LLMError | None = None
        for model in self.models:
            if model in self._unavailable:
                continue
            body = {
                "model": model,
                "temperature": 0,
                "response_format": response_format(schema),
                "messages": [{"role": "user", "content": prompt}],
            }
            for attempt in range(self._retries + 1):
                try:
                    response = await self._post(body)
                except httpx.HTTPError as exc:
                    last_error = LLMError(f"{model}: {type(exc).__name__}: {exc}")
                else:
                    if response.status_code == 200:
                        self.last_model = model
                        return _content(response, model)
                    last_error = LLMError(
                        f"{model}: HTTP {response.status_code}: {response.text[:300]}"
                    )
                    if response.status_code not in RETRY_STATUS:
                        raise last_error
                    if response.headers.get("x-ratelimit-limit-req-minute") == "0":
                        self._unavailable.add(model)
                        break
                if attempt < self._retries:
                    await self._sleep(2**attempt * 2)
        raise last_error or LLMError(f"no usable model among: {', '.join(self.models)}")

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        async with self._gate:
            await self._limiter.acquire(self.url)
            return await self._client.post(self.url, headers=self._headers, json=body)


def _content(response: httpx.Response, model: str) -> str:
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"{model}: unexpected response shape ({exc!r})") from exc
    if not isinstance(content, str):
        raise LLMError(f"{model}: reply content is not text")
    return content


def model_list(primary: str, fallbacks: str) -> list[str]:
    return [primary, *(m.strip() for m in fallbacks.split(",") if m.strip())]


def build_chat_client(
    settings: Settings,
    client: httpx.AsyncClient,
    limiter: Limiter,
    gate: asyncio.Semaphore,
) -> ChatClient:
    provider = settings.llm_provider
    key = getattr(settings, f"{provider}_api_key")
    if not key:
        raise LLMError(
            f"{provider.upper()}_API_KEY is not set; add it to .env or run with --rules-only"
        )
    models = model_list(
        getattr(settings, f"{provider}_model"), getattr(settings, f"{provider}_fallback_models")
    )
    return ChatClient(PROVIDERS[provider], key, models, client, limiter, gate)

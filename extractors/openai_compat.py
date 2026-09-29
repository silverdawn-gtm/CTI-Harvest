"""Client for OpenAI-style chat-completion APIs (Mistral, xAI Grok).

make_complete() returns complete(prompt, response_schema=None) -> JSON string.
It tries each model in order. Rate limits and server errors are retried with
backoff; a model the account has no allowance for (limit 0 req/min) is skipped
for good. `complete.last_model` records which one answered. The client is
thread-safe, so the pipeline can call it for several sentences at once.
"""
import time

import httpx

RETRY_STATUS = {429, 500, 502, 503}


def json_object_format(response_schema):
    """JSON mode without a schema (the reply is still checked by the parser)."""
    return {"type": "json_object"}


def json_schema_format(response_schema):
    """Structured output constrained by the schema, when one is given."""
    if response_schema is None:
        return {"type": "json_object"}
    return {"type": "json_schema", "json_schema": {"name": "extraction", "schema": response_schema}}


def make_complete(url, api_key, models, response_format=json_object_format, retries=2, client=None,
                  sleep=time.sleep):
    client = client or httpx.Client(timeout=120)
    headers = {"Authorization": f"Bearer {api_key}"}
    unavailable = set()

    def complete(prompt, response_schema=None):
        last_err = None
        for model in models:
            if model in unavailable:
                continue
            for attempt in range(retries + 1):
                response = client.post(url, headers=headers, json={
                    "model": model,
                    "temperature": 0,
                    "response_format": response_format(response_schema),
                    "messages": [{"role": "user", "content": prompt}],
                })
                if response.status_code == 200:
                    complete.last_model = model
                    return response.json()["choices"][0]["message"]["content"]
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as err:
                    last_err = err
                if response.status_code not in RETRY_STATUS:
                    raise last_err
                if response.headers.get("x-ratelimit-limit-req-minute") == "0":
                    unavailable.add(model)
                    break
                if attempt < retries:
                    sleep(2 ** attempt * 2)
        if last_err is None:
            raise RuntimeError(f"no usable model among: {', '.join(models)}")
        raise last_err

    complete.last_model = None
    return complete

"""Thin Mistral client: returns a complete(prompt) -> JSON string function.

Tries each model in order. Rate limits and server errors are retried with backoff;
a model the account has no allowance for (limit 0 req/min) is skipped for good.
`complete.last_model` records which one answered.
"""
import time

import httpx

URL = "https://api.mistral.ai/v1/chat/completions"
RETRY_STATUS = {429, 500, 502, 503}


def make_complete(api_key, models, retries=2, client=None, sleep=time.sleep):
    client = client or httpx.Client(timeout=120)
    headers = {"Authorization": f"Bearer {api_key}"}
    unavailable = set()

    def complete(prompt, response_schema=None):  # JSON mode only; schema not sent
        last_err = None
        for model in models:
            if model in unavailable:
                continue
            for attempt in range(retries + 1):
                response = client.post(URL, headers=headers, json={
                    "model": model,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
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
            raise RuntimeError(f"no usable Mistral model among: {', '.join(models)}")
        raise last_err

    complete.last_model = None
    return complete

"""Thin Gemini client: returns a complete(prompt) -> JSON string function.

Tries each model in order; a model that stays overloaded (429/5xx) after a few
retries hands over to the next. A model whose daily quota is used up is skipped
immediately and for the rest of the process. `complete.last_model` records which
one answered. A JSON schema can be passed per call to constrain the reply.
"""
import json
import time

from google import genai
from google.genai import errors, types


RETRY_STATUS = {429, 500, 503}


def _is_daily_quota(err):
    return err.code == 429 and "PerDay" in json.dumps(err.details or {})


def make_complete(api_key, models, retries=2, client=None, sleep=time.sleep):
    client = client or genai.Client(api_key=api_key)
    exhausted = set()

    def complete(prompt, response_schema=None):
        config = types.GenerateContentConfig(
            temperature=0,
            response_mime_type="application/json",
            response_json_schema=response_schema,
        )
        last_err = None
        for model in models:
            if model in exhausted:
                continue
            for attempt in range(retries + 1):
                try:
                    text = client.models.generate_content(model=model, contents=prompt, config=config).text
                    complete.last_model = model
                    return text
                except errors.APIError as err:
                    if err.code not in RETRY_STATUS:
                        raise
                    last_err = err
                    if _is_daily_quota(err):
                        exhausted.add(model)
                        break
                    if attempt < retries:
                        sleep(2 ** attempt * 3)
        if last_err is None:
            raise RuntimeError(f"daily quota used up for every model: {', '.join(models)}")
        raise last_err

    complete.last_model = None
    return complete

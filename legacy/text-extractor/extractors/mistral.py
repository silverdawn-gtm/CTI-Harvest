"""Mistral client: JSON mode (Mistral's free models don't take a response schema)."""
import time

from extractors import openai_compat

URL = "https://api.mistral.ai/v1/chat/completions"


def make_complete(api_key, models, retries=2, client=None, sleep=time.sleep):
    return openai_compat.make_complete(URL, api_key, models, openai_compat.json_object_format,
                                       retries=retries, client=client, sleep=sleep)

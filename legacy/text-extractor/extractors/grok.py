"""xAI Grok client: OpenAI-style API with structured outputs (the reply is constrained by the schema)."""
import time

from extractors import openai_compat

URL = "https://api.x.ai/v1/chat/completions"


def make_complete(api_key, models, retries=2, client=None, sleep=time.sleep):
    return openai_compat.make_complete(URL, api_key, models, openai_compat.json_schema_format,
                                       retries=retries, client=client, sleep=sleep)

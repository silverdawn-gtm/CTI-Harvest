import json

import httpx

from extractors.grok import URL, make_complete


def ok(content):
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def client_for(script):
    """`script` maps model -> list of responses returned in turn; requests are recorded."""
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append({"url": str(request.url), "auth": request.headers["authorization"], **body})
        return script[body["model"]].pop(0)

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_calls_the_xai_chat_completions_endpoint():
    client, calls = client_for({"grok-a": [ok('{"x": 1}')]})
    complete = make_complete("key-1", ["grok-a"], client=client, sleep=lambda s: None)
    assert complete("prompt") == '{"x": 1}'
    assert URL == "https://api.x.ai/v1/chat/completions" and calls[0]["url"] == URL
    assert calls[0]["auth"] == "Bearer key-1"
    assert calls[0]["temperature"] == 0
    assert calls[0]["messages"] == [{"role": "user", "content": "prompt"}]
    assert complete.last_model == "grok-a"


def test_sends_the_response_schema_as_structured_output():
    client, calls = client_for({"grok-a": [ok("{}")]})
    schema = {"type": "object", "properties": {"entities": {"type": "array"}}}
    make_complete("k", ["grok-a"], client=client, sleep=lambda s: None)("p", response_schema=schema)
    assert calls[0]["response_format"] == {
        "type": "json_schema", "json_schema": {"name": "extraction", "schema": schema}}


def test_without_a_schema_uses_json_mode():
    client, calls = client_for({"grok-a": [ok("{}")]})
    make_complete("k", ["grok-a"], client=client, sleep=lambda s: None)("p")
    assert calls[0]["response_format"] == {"type": "json_object"}


def test_rate_limited_model_falls_back_to_the_next():
    client, calls = client_for({"grok-a": [httpx.Response(429)] * 3, "grok-b": [ok("{}")]})
    complete = make_complete("k", ["grok-a", "grok-b"], client=client, sleep=lambda s: None)
    assert complete("p") == "{}"
    assert [c["model"] for c in calls] == ["grok-a"] * 3 + ["grok-b"]
    assert complete.last_model == "grok-b"

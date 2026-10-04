import json

import httpx
import pytest

from extractors.mistral import make_complete


def ok(content):
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def rate_limited(limit_per_minute):
    return httpx.Response(429, json={"message": "Rate limit exceeded"},
                          headers={"x-ratelimit-limit-req-minute": str(limit_per_minute)})


def client_for(script):
    """`script` maps model -> list of responses returned in turn; requests are recorded."""
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        return script[body["model"]].pop(0)

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_sends_json_mode_request_at_temperature_zero():
    client, calls = client_for({"a": [ok('{"x": 1}')]})
    complete = make_complete("k", ["a"], client=client, sleep=lambda s: None)
    assert complete("prompt") == '{"x": 1}'
    assert calls[0]["temperature"] == 0
    assert calls[0]["response_format"] == {"type": "json_object"}
    assert calls[0]["messages"] == [{"role": "user", "content": "prompt"}]
    assert complete.last_model == "a"


def test_retries_rate_limit_on_same_model():
    client, calls = client_for({"a": [rate_limited(30), ok("{}")]})
    complete = make_complete("k", ["a"], client=client, sleep=lambda s: None)
    assert complete("p") == "{}"
    assert [c["model"] for c in calls] == ["a", "a"]


def test_model_with_zero_allowance_is_skipped_for_good():
    client, calls = client_for({"a": [rate_limited(0)], "b": [ok("1"), ok("2")]})
    complete = make_complete("k", ["a", "b"], client=client, sleep=lambda s: None)
    complete("p")
    complete("p")
    assert [c["model"] for c in calls] == ["a", "b", "b"]


def test_raises_after_retries_run_out():
    client, _ = client_for({"a": [httpx.Response(503)] * 3})
    complete = make_complete("k", ["a"], retries=2, client=client, sleep=lambda s: None)
    with pytest.raises(httpx.HTTPStatusError):
        complete("p")


def test_other_errors_are_not_retried():
    client, calls = client_for({"a": [httpx.Response(401, json={"message": "bad key"})]})
    complete = make_complete("k", ["a", "b"], client=client, sleep=lambda s: None)
    with pytest.raises(httpx.HTTPStatusError):
        complete("p")
    assert len(calls) == 1


def test_accepts_and_ignores_response_schema():
    client, calls = client_for({"a": [ok("{}")]})
    complete = make_complete("k", ["a"], client=client, sleep=lambda s: None)
    assert complete("p", response_schema={"type": "object"}) == "{}"
    assert calls[0]["response_format"] == {"type": "json_object"}

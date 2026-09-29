from types import SimpleNamespace

import pytest
from google.genai import errors

from extractors.gemini import make_complete


def quota_error(per_day):
    quota_id = "GenerateRequestsPerDayPerProjectPerModel-FreeTier" if per_day else "GenerateRequestsPerMinute"
    return errors.ClientError(429, {"error": {
        "code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED",
        "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                     "violations": [{"quotaId": quota_id}]}],
    }})


class FakeClient:
    """Stands in for genai.Client; `script` maps model -> list of results/errors to return in turn."""

    def __init__(self, script):
        self.script = script
        self.calls = []
        self.models = SimpleNamespace(generate_content=self._generate)

    def _generate(self, model, contents, config):
        self.calls.append(model)
        result = self.script[model].pop(0)
        if isinstance(result, Exception):
            raise result
        return SimpleNamespace(text=result)


def test_returns_first_model_reply():
    client = FakeClient({"a": ['{"ok": 1}']})
    complete = make_complete(None, ["a", "b"], client=client, sleep=lambda s: None)
    assert complete("p") == '{"ok": 1}'
    assert complete.last_model == "a"


def test_daily_quota_moves_to_next_model_without_retrying():
    client = FakeClient({"a": [quota_error(per_day=True)], "b": ['{"ok": 1}']})
    complete = make_complete(None, ["a", "b"], client=client, sleep=lambda s: None)
    assert complete("p") == '{"ok": 1}'
    assert client.calls == ["a", "b"]


def test_daily_quota_is_remembered_for_later_calls():
    client = FakeClient({"a": [quota_error(per_day=True)], "b": ["1", "2"]})
    complete = make_complete(None, ["a", "b"], client=client, sleep=lambda s: None)
    complete("p")
    complete("p")
    assert client.calls == ["a", "b", "b"]


def test_per_minute_quota_is_retried_on_same_model():
    client = FakeClient({"a": [quota_error(per_day=False), '{"ok": 1}']})
    complete = make_complete(None, ["a"], client=client, sleep=lambda s: None)
    assert complete("p") == '{"ok": 1}'
    assert client.calls == ["a", "a"]


def test_raises_when_every_model_is_out_of_quota():
    client = FakeClient({"a": [quota_error(per_day=True)], "b": [quota_error(per_day=True)]})
    complete = make_complete(None, ["a", "b"], client=client, sleep=lambda s: None)
    with pytest.raises(errors.ClientError):
        complete("p")


def test_uses_a_per_call_response_schema():
    seen = []

    class Recording(FakeClient):
        def _generate(self, model, contents, config):
            seen.append(config.response_json_schema)
            return super()._generate(model, contents, config)

    client = Recording({"a": ["{}", "{}"]})
    complete = make_complete(None, ["a"], client=client, sleep=lambda s: None)
    complete("p", response_schema={"type": "object", "title": "custom"})
    complete("p")
    assert seen[0]["title"] == "custom"
    assert seen[1] != seen[0]

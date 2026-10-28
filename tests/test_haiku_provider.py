"""Haiku provider unit tests with a fake Anthropic client (no network, no API key spend)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from login_anomaly.agentic.cases import CaseInvestigationInput
from login_anomaly.agentic.haiku_provider import HaikuInvestigatorProvider
from login_anomaly.agentic.provider import FinalResponse, ToolRequest


@dataclass
class _FakeBlock:
    type: str
    name: str | None = None
    id: str | None = None
    input: dict | None = None
    text: str | None = None


class _FakeMessages:
    def __init__(self, responses: list[object]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def create(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls += 1
        return self._responses.pop(0)


class _FakeClient:
    def __init__(self, responses: list[object]) -> None:
        self.messages = _FakeMessages(responses)


def _case() -> CaseInvestigationInput:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return CaseInvestigationInput(
        case_id="case-1",
        dataset_id="dataset-1",
        case_kind="rule_backed",
        event_ids=("evt-1",),
        priority_hint="rule_high",
        first_seen=now,
        last_seen=now,
    )


def test_haiku_requests_tool_then_final(monkeypatch: pytest.MonkeyPatch) -> None:
    tool_response = SimpleNamespace(
        content=[_FakeBlock(type="tool_use", name="get_alert_evidence", id="tu_1", input={"alert_id": "case-1"})],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
    )
    final_response = SimpleNamespace(
        content=[
            _FakeBlock(
                type="text",
                text=(
                    '{"alert_id":"case-1","verdict":"inconclusive","confidence":0.0,"evidence":[],'
                    '"tool_calls":[],"justification":"Need more evidence.","limitations":["fixture"],'
                    '"hypotheses":[],"risk_level":"medium"}'
                ),
            )
        ],
        usage=SimpleNamespace(input_tokens=12, output_tokens=20),
    )
    fake = _FakeClient([tool_response, final_response])

    provider = HaikuInvestigatorProvider.__new__(HaikuInvestigatorProvider)
    provider.api_key = "test-key"
    provider.model = "claude-haiku-5-5"
    provider.mode = "llm"
    provider.provider_id = "anthropic-haiku"
    provider.max_tokens = 1024
    from login_anomaly.agentic.haiku_provider import ProviderUsage

    provider.usage = ProviderUsage()
    provider._client = fake
    provider._messages = []
    provider._pending_tool_use_id = None
    provider._observation_count = 0

    case = _case()
    first = provider.next_action(case, ())
    assert isinstance(first, ToolRequest)
    assert first.tool_name == "get_alert_evidence"

    second = provider.next_action(case, ({"events": [{"event_id": "evt-1", "outcome": "failure"}]},))
    assert isinstance(second, FinalResponse)
    assert second.result["verdict"] == "inconclusive"
    assert provider.usage.tokens_in == 22
    assert provider.usage.tokens_out == 25
    assert fake.messages.calls == 2


def _provider(responses: list[object]) -> tuple[HaikuInvestigatorProvider, _FakeClient]:
    from login_anomaly.agentic.haiku_provider import ProviderUsage

    fake = _FakeClient(responses)
    provider = HaikuInvestigatorProvider.__new__(HaikuInvestigatorProvider)
    provider.api_key = "test-key"
    provider.model = "claude-haiku-5-5"
    provider.mode = "llm"
    provider.provider_id = "anthropic-haiku"
    provider.max_tokens = 1024
    provider.usage = ProviderUsage()
    provider._client = fake
    provider._messages = []
    provider._pending_tool_use_id = None
    provider._observation_count = 0
    return provider, fake


def test_haiku_reads_a_json_object_wrapped_in_prose() -> None:
    body = (
        "Finding:\n```json\n"
        '{"verdict":"malicious","confidence":"0.8","risk_level":"HIGH",'
        '"evidence":[{"event_id":"evt-1","field":"outcome","summary":"Repeated failures."}, "skip"],'
        '"justification":"Failures pile up from one IP.","limitations":["Synthetic."],'
        '"hypotheses":[{"statement":"Password spray.","stance":"supports","evidence_event_ids":["evt-1"]}]}\n'
        "```\nThat is the write-up."
    )
    provider, fake = _provider(
        [SimpleNamespace(content=[_FakeBlock(type="text", text=body)], usage=SimpleNamespace(input_tokens=4, output_tokens=8))]
    )
    action = provider.next_action(_case(), ())
    assert isinstance(action, FinalResponse)
    assert action.result["verdict"] == "malicious"
    assert action.result["confidence"] == 0.8
    assert action.result["risk_level"] == "high"
    assert action.result["alert_id"] == "case-1"
    assert action.result["evidence"] == [{"event_id": "evt-1", "field": "outcome", "summary": "Repeated failures."}]
    assert fake.messages.calls == 1


def test_truncated_reply_is_not_read_as_a_nested_object() -> None:
    from login_anomaly.agentic.haiku_provider import _extract_json

    text = '{"verdict":"malicious","evidence":[{"event_id":"evt-1","field":"outcome","summary":"cut'
    assert _extract_json(text) is None


def test_haiku_asks_once_more_when_the_reply_is_not_json() -> None:
    prose = SimpleNamespace(content=[_FakeBlock(type="text", text="This looks malicious.")], usage=SimpleNamespace(input_tokens=3, output_tokens=4))
    repaired = SimpleNamespace(
        content=[
            _FakeBlock(
                type="text",
                text='{"verdict":"benign","confidence":0.4,"justification":"Travel fits the account.","limitations":[]}',
            )
        ],
        usage=SimpleNamespace(input_tokens=5, output_tokens=6),
    )
    provider, fake = _provider([prose, repaired])
    action = provider.next_action(_case(), ())
    assert isinstance(action, FinalResponse)
    assert action.result["verdict"] == "benign"
    assert provider.usage.tokens_in == 8
    assert provider.usage.tokens_out == 10
    assert fake.messages.calls == 2


def test_haiku_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        HaikuInvestigatorProvider(api_key=None)

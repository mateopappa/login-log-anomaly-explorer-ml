"""Backward-compatible investigation result parsing with optional hypotheses."""

from login_anomaly.agentic.contracts import parse_investigation_result


def test_parse_without_optional_fields() -> None:
    result = parse_investigation_result(
        {
            "alert_id": "c1",
            "verdict": "inconclusive",
            "confidence": 0.0,
            "evidence": [],
            "tool_calls": [],
            "justification": "Not enough evidence.",
            "limitations": ["Sparse window."],
        }
    )
    assert result.hypotheses == ()
    assert result.risk_level is None


def test_parse_with_hypotheses_and_risk() -> None:
    result = parse_investigation_result(
        {
            "alert_id": "c1",
            "verdict": "malicious",
            "confidence": 0.7,
            "evidence": [{"event_id": "e1", "field": "outcome", "summary": "failure burst"}],
            "tool_calls": [],
            "justification": "Repeated failures.",
            "limitations": ["Synthetic data only."],
            "risk_level": "high",
            "hypotheses": [
                {
                    "statement": "Credential stuffing against one account",
                    "stance": "supports",
                    "evidence_event_ids": ["e1"],
                }
            ],
        }
    )
    assert result.risk_level == "high"
    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].stance == "supports"

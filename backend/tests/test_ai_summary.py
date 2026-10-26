"""AI-Assisted Analysis engine tests.

The engine is optional and gated behind GEMINI_API_KEY. These tests mock the
Gemini REST call so no key or network is required, and verify the no-key no-op,
response parsing, graceful failure, and PDF-section rendering.
"""

import json
import types
from unittest.mock import MagicMock, patch

from app.engines.ai_summary import AiSummaryEngine
from app.engines.report_generator import ReportGenerator


def _finding(title="SQL Injection", sev="High"):
    f = types.SimpleNamespace(
        title=title, severity=sev, cwe_id="CWE-89", cve_id=None, cvss_score=7.5,
        classification="Confirmed", confidence_score=None, ml_prediction=None)
    return f


_AI_JSON = {
    "executive_summary": "One high-severity SQL injection was confirmed.",
    "key_findings": [{"title": "SQL Injection", "risk": "Data exfiltration.",
                      "fix": "Use parameterised queries."}],
    "priority_actions": ["Patch the SQL injection", "Re-scan"],
}


def _mock_response():
    """A fake requests.Response whose JSON carries _AI_JSON as Gemini output."""
    resp = MagicMock(status_code=200)
    resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": json.dumps(_AI_JSON)}]}}]
    }
    return resp


def test_disabled_without_key(monkeypatch):
    # Isolate from any provider key that .env / the environment may set.
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    e = AiSummaryEngine(api_key="")
    assert e.enabled is False
    assert e.summarise([_finding()]) is None


def test_provider_and_default_model():
    e = AiSummaryEngine(api_key="AIza-test")
    assert e.enabled is True
    assert e.provider == "gemini"
    assert e.model == "gemini-flash-latest"


def test_summarise_parses_response():
    e = AiSummaryEngine(api_key="AIza-test")
    with patch("requests.post", return_value=_mock_response()) as post:
        out = e.summarise([_finding()])
    assert out == _AI_JSON
    # Hit the Gemini REST endpoint.
    assert "generativelanguage.googleapis.com" in post.call_args[0][0]


def test_summarise_degrades_on_error():
    e = AiSummaryEngine(api_key="AIza-test")
    with patch("requests.post", side_effect=RuntimeError("network down")):
        assert e.summarise([_finding()]) is None  # no exception, just None


def test_empty_findings_returns_none():
    assert AiSummaryEngine(api_key="AIza-test").summarise([]) is None


def test_ai_section_renders_flowables():
    styles = ReportGenerator._make_styles()
    story = ReportGenerator()._ai_section(_AI_JSON, styles)
    assert isinstance(story, list) and len(story) > 3

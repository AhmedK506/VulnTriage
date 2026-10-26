"""Confidence Engine tests.

These exercise the pure `compute_score()` path on lightweight stand-in findings
(see app/engines/eval/finding_stub.py), so they need no database or app context.
"""

from app.engines.confidence_engine import ConfidenceEngine
from app.engines.eval.finding_stub import FindingStub


def test_weights_sum_to_100():
    assert sum(ConfidenceEngine.WEIGHTS.values()) == 100


def test_breakdown_structure_v2():
    engine = ConfidenceEngine()
    f = FindingStub("x", is_true_positive=True, scanner_count=1)
    score, classification, breakdown = engine.compute_score(f)
    assert 0 <= score <= 100
    assert breakdown["version"] == 2
    assert set(breakdown["factors"]) == set(ConfidenceEngine.WEIGHTS)
    assert isinstance(breakdown["rationale"], str) and breakdown["rationale"]
    for info in breakdown["factors"].values():
        assert {"raw_score", "weight", "contribution", "reason"} <= set(info)


def test_strong_true_positive_is_confirmed():
    # Multi-scanner + CVE + exploit + PoC-confirmed should land "Confirmed".
    f = FindingStub(
        "RCE", is_true_positive=True, severity="Critical", scanner_count=2,
        scanner_sources=["nessus", "nuclei"], cve_id="CVE-2024-1709",
        cwe_id="CWE-94", exploit_available=True, attack_vector="NETWORK",
        _ml_priority="Critical",
    )
    score, classification, _ = ConfidenceEngine().compute_score(f)
    assert classification == "Confirmed"
    assert score >= 70


def test_lone_low_signal_is_not_confirmed():
    # A single-scanner header finding with no corroboration should be dismissed.
    f = FindingStub(
        "Missing header", is_true_positive=False, severity="Low",
        scanner_count=1, scanner_sources=["zap"], cwe_id="CWE-1021",
        _ml_priority="Low",
    )
    score, classification, _ = ConfidenceEngine().compute_score(f)
    assert classification == "Not Confirmed"
    assert score < 40


def test_poc_confirmed_overrides_to_confirmed():
    # Even a single-scanner finding is forced to Confirmed by a confirmed PoC.
    f = FindingStub(
        "Reflected XSS", is_true_positive=True, severity="Medium",
        scanner_count=1, scanner_sources=["zap"], cwe_id="CWE-79",
        _ml_priority="Medium", _poc_results=["confirmed"],
    )
    score, classification, breakdown = ConfidenceEngine().compute_score(f)
    assert classification == "Confirmed"
    assert score >= 75
    assert "PoC" in breakdown["rationale"]


def test_informational_severity_is_classified_informational():
    f = FindingStub("Wappalyzer Technology Detection", is_true_positive=False,
                    severity="Informational", scanner_count=1, scanner_sources=["nuclei"])
    _, classification, _ = ConfidenceEngine().compute_score(f)
    assert classification == "Informational"


def test_weak_poc_type_does_not_override_to_confirmed():
    # A generic payload_reflection 'confirmed' must NOT force Confirmed — it only
    # proves input is reflected, not that the reported vuln (e.g. buffer overflow)
    # is real. It may still land in review, but never auto-Confirmed on its own.
    f = FindingStub("Buffer Overflow", is_true_positive=False, severity="Medium",
                    scanner_count=1, scanner_sources=["zap"],
                    _poc_results=["confirmed"], _poc_type="payload_reflection")
    _, classification, _ = ConfidenceEngine().compute_score(f)
    assert classification != "Confirmed"


def test_severity_consistency_neutral_without_cvss_vector():
    # No attack_vector => ML severity cannot corroborate => neutral (50), not a penalty.
    f = FindingStub(
        "Lone finding, no vector", is_true_positive=False, severity="High",
        scanner_count=1, _ml_priority="Low",  # would "diverge" if not neutralised
    )
    _, _, breakdown = ConfidenceEngine().compute_score(f)
    sc = breakdown["factors"]["severity_consistency"]
    assert sc["raw_score"] == 50.0
    assert "no cvss vector" in sc["reason"].lower()

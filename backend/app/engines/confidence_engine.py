"""
Confidence Engine (Phase 6)

Produces a composite *confidence* score (0-100) for each normalised finding and
classifies it as Confirmed / Needs Manual Verification / Not Confirmed.

Design principle — confidence is NOT severity
---------------------------------------------
"Confidence" here means **how likely the finding is a true positive** (worth an
analyst's time), NOT how damaging it would be if real. Those are different axes:
a Critical-severity finding is not inherently more likely to be *real* than a
Low one. Severity is already captured by CVSS/ML priority and is reported
separately. Every factor below is therefore chosen as a *reliability* signal.

Factors and weight rationale (weights sum to 100)
-------------------------------------------------
  scanner_agreement     25  Independent corroboration. The single strongest
                            passive signal: if N separate tools flag the same
                            issue it is far less likely to be one tool's quirk.
  severity_consistency  20  Does the ML severity model AGREE with the scanner's
                            reported severity? Agreement means the finding's
                            metadata is internally consistent (not a mis-parse or
                            noisy entry). This is the ML model's contribution to
                            *confidence* — via agreement, not via magnitude.
  cve_availability      15  A finding mapped to a catalogued CVE corresponds to a
                            known, real vulnerability class — more credible.
  exploit_availability  15  A known public exploit means the class is real and
                            weaponised, raising the prior that it is genuine.
  poc_validation        15  Direct active evidence from our own controlled check.
                            (A *confirmed* PoC also hard-overrides the class.)
  cwe_mapping            10  A recognised weakness class — weak corroboration that
                            the finding is well-formed rather than spurious.

These weights are a documented, defensible default. They are exposed via the
`WEIGHTS` dict and the engine is weight-agnostic, so they can be tuned without
code changes.

Classification thresholds:
  70-100  ->  Confirmed
  40-69   ->  Needs Manual Verification
  0-39    ->  Not Confirmed
"""

from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.confidence_score import ConfidenceScore


# Validation types strong/specific enough to hard-override to "Confirmed".
# Excludes the generic payload_reflection / response_analysis checks, which
# confirm on mere reflection or a Server header and would over-confirm.
STRONG_POC_TYPES = {
    "xss_check", "sqli_check", "open_redirect_check",
    "lfi_check", "header_check", "cors_check",
}

# Ordinal ranking shared by ML priority and scanner severity, used to measure
# agreement between the two (severity_consistency factor).
_SEVERITY_ORDINAL = {
    "critical": 3, "high": 2, "medium": 1, "low": 0,
    "informational": 0, "info": 0,
}


class ConfidenceEngine:
    # Weights must sum to 100. See module docstring for the rationale.
    WEIGHTS = {
        "scanner_agreement": 25,
        "severity_consistency": 20,
        "cve_availability": 15,
        "exploit_availability": 15,
        "poc_validation": 15,
        "cwe_mapping": 10,
    }

    def __init__(self, weights: dict | None = None):
        # Allow callers (e.g. the evaluation harness) to inject alternative
        # weights for sensitivity analysis without touching the class default.
        self.weights = dict(weights) if weights else dict(self.WEIGHTS)

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #
    def compute_score(self, finding) -> tuple[float, str, dict]:
        """Pure scoring: returns (score, classification, breakdown) with NO DB
        writes. Accepts any object exposing the finding's attributes, so the
        evaluation harness can score lightweight stand-ins. `score_finding`
        wraps this with persistence."""
        factors = self._compute_factors(finding)
        total = sum((factors[k]["raw"] / 100) * self.weights[k] for k in self.weights)
        total = round(min(max(total, 0), 100), 2)

        # PoC override: a confirmed *vulnerability-specific* validation forces
        # "Confirmed". Only STRONG, type-matched checks qualify — the generic
        # payload_reflection / response_analysis checks confirm on mere input
        # reflection or a Server header, which does NOT prove the reported vuln
        # (e.g. a spurious "Buffer Overflow" or informational tech-detection), so
        # they must not hard-override. They still contribute via the poc factor.
        poc_confirmed = any(
            v.result == "confirmed" and v.validation_type in STRONG_POC_TYPES
            for v in finding.poc_validations.all()
        )
        if poc_confirmed:
            classification = "Confirmed"
            # Guarantee the Confirmed band (>=70) but keep score variation: map the
            # finding's own evidence strength into 70-100 so confirmed findings are
            # still ranked by corroboration (scanners, CVE, exploit, ...) instead of
            # all collapsing to a flat 75. Monotonic, so ordering is preserved.
            total = round(70.0 + (total / 100.0) * 30.0, 2)
            override_note = "PoC actively confirmed the vulnerability — classification forced to Confirmed (score scaled into the 70-100 band)."
        elif (finding.severity or "").strip().lower() in ("informational", "info", "information"):
            # Scanner-rated informational findings (tech/version detection, exposed
            # metadata) are not vulnerabilities to confirm/deny — bucket them as
            # "Informational" so testers aren't confused by a "Not Confirmed" verdict.
            classification = "Informational"
            override_note = None
        else:
            classification = self._classify(total)
            override_note = None

        breakdown = {
            "version": 2,
            "factors": {
                k: {
                    "raw_score": round(factors[k]["raw"], 1),
                    "weight": self.weights[k],
                    "contribution": round((factors[k]["raw"] / 100) * self.weights[k], 2),
                    "reason": factors[k]["reason"],
                }
                for k in self.weights
            },
            "rationale": self._build_rationale(
                classification, total, factors, override_note
            ),
        }
        return total, classification, breakdown

    def score_finding(self, finding: NormalizedFinding) -> ConfidenceScore:
        """Compute and persist a ConfidenceScore for the given finding."""
        total, classification, breakdown = self.compute_score(finding)
        factors = breakdown["factors"]

        cs = finding.confidence_score or ConfidenceScore(finding_id=finding.id)
        cs.score = total
        cs.classification = classification
        # Persist the legacy scalar columns for back-compat / quick queries.
        cs.scanner_agreement_score = factors["scanner_agreement"]["raw_score"]
        cs.cve_availability_score = factors["cve_availability"]["raw_score"]
        cs.cwe_mapping_score = factors["cwe_mapping"]["raw_score"]
        cs.ml_priority_score = factors["severity_consistency"]["raw_score"]  # repurposed
        cs.exploit_availability_score = factors["exploit_availability"]["raw_score"]
        cs.poc_validation_score = factors["poc_validation"]["raw_score"]
        cs.factor_breakdown = breakdown

        finding.classification = classification
        db.session.add(cs)
        db.session.add(finding)
        return cs

    def score_all(self) -> int:
        """Score every finding that doesn't yet have a confidence score."""
        findings = (
            NormalizedFinding.query
            .outerjoin(ConfidenceScore, ConfidenceScore.finding_id == NormalizedFinding.id)
            .filter(ConfidenceScore.id.is_(None))
            .all()
        )
        for f in findings:
            self.score_finding(f)
        db.session.commit()
        return len(findings)

    def rescore_finding(self, finding: NormalizedFinding) -> ConfidenceScore:
        """Recompute score after new data (e.g. after PoC validation)."""
        cs = self.score_finding(finding)
        db.session.commit()
        return cs

    # ------------------------------------------------------------------ #
    #  Factor computation — each returns {"raw": float, "reason": str}    #
    # ------------------------------------------------------------------ #
    def _compute_factors(self, finding: NormalizedFinding) -> dict:
        return {
            "scanner_agreement": self._scanner_agreement(finding),
            "severity_consistency": self._severity_consistency(finding),
            "cve_availability": self._cve_factor(finding),
            "exploit_availability": self._exploit_factor(finding),
            "poc_validation": self._poc_factor(finding),
            "cwe_mapping": self._cwe_factor(finding),
        }

    @staticmethod
    def _scanner_agreement(finding: NormalizedFinding) -> dict:
        count = finding.scanner_count or 1
        raw = min(count * 33.3, 100)
        if count >= 2:
            srcs = ", ".join(finding.scanner_sources or []) or f"{count} scanners"
            reason = f"Corroborated by {count} independent scanners ({srcs})."
        else:
            reason = "Reported by a single scanner — no cross-tool corroboration."
        return {"raw": raw, "reason": reason}

    def _severity_consistency(self, finding: NormalizedFinding) -> dict:
        ml = finding.ml_prediction
        sev = (finding.severity or "").strip().lower()
        sev_ord = _SEVERITY_ORDINAL.get(sev)

        if not ml or ml.predicted_priority is None:
            return {"raw": 50.0,
                    "reason": "No ML priority available to corroborate severity (neutral)."}
        # The ML model is trained on CVSS v3 vectors. When a scanner provides no
        # vector (common for web scanners like ZAP), the prediction is driven by
        # empty features and is not a trustworthy corroboration — stay neutral
        # rather than penalise a finding for missing upstream metadata.
        if not finding.attack_vector:
            return {"raw": 50.0,
                    "reason": "No CVSS vector supplied by the scanner, so ML "
                              "severity cannot corroborate (neutral)."}
        if sev_ord is None:
            return {"raw": 50.0,
                    "reason": f"Scanner severity '{finding.severity}' not comparable (neutral)."}

        ml_ord = _SEVERITY_ORDINAL.get(ml.predicted_priority.strip().lower())
        if ml_ord is None:
            return {"raw": 50.0, "reason": "ML priority not comparable (neutral)."}

        distance = abs(ml_ord - sev_ord)
        raw = {0: 100.0, 1: 60.0, 2: 25.0}.get(distance, 0.0)
        if distance == 0:
            verdict = "matches"
        elif distance == 1:
            verdict = "is one band off from"
        else:
            verdict = "diverges sharply from"
        reason = (f"ML priority '{ml.predicted_priority}' {verdict} scanner "
                  f"severity '{finding.severity}'.")
        # Note provenance when the ML input vector was inferred from a CWE profile
        # rather than supplied by the scanner/NVD (transient flag set by enrichment).
        if getattr(finding, "_vector_inferred", False):
            reason += " (ML severity from a CWE-typical CVSS profile)"
        return {"raw": raw, "reason": reason}

    @staticmethod
    def _cve_factor(finding: NormalizedFinding) -> dict:
        if finding.cve_id:
            return {"raw": 100.0, "reason": f"Mapped to catalogued {finding.cve_id}."}
        return {"raw": 0.0, "reason": "No CVE mapping."}

    @staticmethod
    def _cwe_factor(finding: NormalizedFinding) -> dict:
        if finding.cwe_id:
            return {"raw": 100.0, "reason": f"Classified as {finding.cwe_id}."}
        return {"raw": 0.0, "reason": "No CWE mapping."}

    @staticmethod
    def _exploit_factor(finding: NormalizedFinding) -> dict:
        if finding.exploit_available:
            return {"raw": 100.0, "reason": "Known public exploit available."}
        vuln = finding.source_vulnerability
        if vuln and vuln.raw_data:
            ea = str(vuln.raw_data.get("exploit_available", "")).lower()
            if ea in ("true", "yes", "1"):
                return {"raw": 100.0, "reason": "Scanner reports a public exploit available."}
        return {"raw": 0.0, "reason": "No known public exploit."}

    @staticmethod
    def _poc_factor(finding: NormalizedFinding) -> dict:
        validations = finding.poc_validations.all()
        if not validations:
            return {"raw": 0.0, "reason": "No PoC validation performed."}
        confirmed = sum(1 for v in validations if v.result == "confirmed")
        total = len(validations)
        raw = (confirmed / total) * 100
        return {"raw": raw,
                "reason": f"{confirmed} of {total} controlled PoC check(s) confirmed."}

    # ------------------------------------------------------------------ #
    #  Helpers                                                            #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _classify(score: float) -> str:
        if score >= 70:
            return "Confirmed"
        if score >= 40:
            return "Needs Manual Verification"
        return "Not Confirmed"

    def _build_rationale(self, classification, total, factors, override_note) -> str:
        """Human-readable one-paragraph explanation of the classification."""
        if override_note:
            return f"{classification} ({total:.0f}/100). {override_note}"

        # Rank factors by their weighted contribution and surface the drivers.
        ranked = sorted(
            factors.items(),
            key=lambda kv: (kv[1]["raw"] / 100) * self.weights[kv[0]],
            reverse=True,
        )
        drivers = [f"{factors[k]['reason']}" for k, _ in ranked
                   if (factors[k]["raw"] / 100) * self.weights[k] >= 5][:3]
        gaps = [factors[k]["reason"] for k, _ in ranked
                if factors[k]["raw"] == 0][:2]

        parts = [f"{classification} ({total:.0f}/100)."]
        if drivers:
            parts.append("Main supporting signals: " + " ".join(drivers))
        if gaps and classification != "Confirmed":
            parts.append("Weakening factors: " + " ".join(gaps))
        return " ".join(parts)

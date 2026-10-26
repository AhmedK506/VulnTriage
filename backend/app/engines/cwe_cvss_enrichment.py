"""
CWE → CVSS-vector enrichment (runs after NVD enrichment, before ML predict).

Fills a *plausible, empirically-derived* CVSS v3 vector onto findings that have a
CWE but no vector (typical of OWASP ZAP), using the per-CWE modal vector mined
from the NVD feeds (see app/ml/cwe_profile_builder.py). Without this, the ML
severity model gets an all-zero feature vector for such findings and predicts
"Low" for everything, so the Confidence Engine's severity_consistency check
cannot contribute.

Precedence: only fills when `attack_vector` is still unset, so a real vector from
the scanner or NVD always wins. Inferred findings are flagged in-memory via
`finding._vector_inferred = True` so the Confidence Engine can note the provenance
in its rationale.
"""

import os
import json

from app import db
from app.models.normalized_finding import NormalizedFinding

# cvssData-style field name (stored on the finding) -> attribute set here.
_FIELDS = [
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact",
    "integrity_impact", "availability_impact",
]


def _profiles_path() -> str:
    """Locate ml_data/cwe_cvss_profiles.json without needing an app context."""
    try:
        from flask import current_app
        model_dir = current_app.config["ML_MODEL_PATH"]      # .../ml_data/models
        return os.path.join(os.path.dirname(model_dir), "cwe_cvss_profiles.json")
    except Exception:
        here = os.path.dirname(os.path.abspath(__file__))     # .../backend/app/engines
        return os.path.normpath(os.path.join(here, "..", "..", "..",
                                             "ml_data", "cwe_cvss_profiles.json"))


def _extract_cwe_number(cwe_id) -> int | None:
    if not cwe_id:
        return None
    import re
    m = re.search(r"(\d+)", str(cwe_id))
    return int(m.group(1)) if m else None


class CweCvssEnrichmentEngine:
    _profiles = None  # cached {"global":..., "by_cwe": {...}}

    def _load(self) -> dict | None:
        if self._profiles is not None:
            return self._profiles
        path = _profiles_path()
        if not os.path.exists(path):
            self._profiles = {}
            return self._profiles
        with open(path) as f:
            CweCvssEnrichmentEngine._profiles = json.load(f)
        return self._profiles

    def _profile_for(self, cwe_number) -> tuple[dict | None, str]:
        profiles = self._load()
        if not profiles:
            return None, "none"
        by_cwe = profiles.get("by_cwe", {})
        if cwe_number is not None and str(cwe_number) in by_cwe:
            return by_cwe[str(cwe_number)], "cwe"
        if profiles.get("global"):
            return profiles["global"], "global"
        return None, "none"

    def enrich_finding(self, finding: NormalizedFinding) -> bool:
        """Fill an inferred vector if the finding lacks one. Returns True if applied."""
        if finding.attack_vector:           # scanner/NVD already supplied a vector
            return False
        cwe_number = _extract_cwe_number(finding.cwe_id)
        profile, src = self._profile_for(cwe_number)
        if not profile or src == "none":
            return False

        for field in _FIELDS:
            setattr(finding, field, profile.get(field))
        if not finding.cvss_vector and profile.get("_vector"):
            finding.cvss_vector = profile["_vector"]
        # Do NOT overwrite a scanner-provided cvss_score / severity; only fill gaps.
        # Prefer the score of the modal vector we actually attached (vector_score)
        # so the displayed score, the inferred vector and the ML band all agree;
        # fall back to the CWE's median for older profiles without vector_score.
        inferred_score = profile.get("vector_score")
        if inferred_score is None:
            inferred_score = profile.get("median_score")
        if finding.cvss_score is None and inferred_score is not None:
            finding.cvss_score = float(inferred_score)

        # Transient provenance flag (not persisted) for the Confidence Engine.
        finding._vector_inferred = True
        finding._vector_inferred_from = "cwe" if src == "cwe" else "global"
        db.session.add(finding)
        return True

    def enrich_all_pending(self) -> int:
        """Enrich every finding that still has no CVSS vector."""
        findings = (
            NormalizedFinding.query
            .filter(NormalizedFinding.attack_vector.is_(None))
            .all()
        )
        applied = 0
        for f in findings:
            if self.enrich_finding(f):
                applied += 1
        db.session.commit()
        return applied

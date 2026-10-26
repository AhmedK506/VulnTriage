"""
NVD Dataset Processor (Phase 4)

Converts raw NVD JSON feed files (downloaded to ml_data/nvd/) into a
pandas DataFrame suitable for training the Random Forest model.

NVD JSON 2.0 format (api.nvd.nist.gov/rest/json/cves/2.0):
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-YYYY-NNNNN",
        "metrics": {
          "cvssMetricV31": [
            { "cvssData": { "baseScore": N, "vectorString": "...", ... } }
          ]
        },
        "weaknesses": [ { "description": [ { "value": "CWE-NNN" } ] } ]
      }
    }
  ]
}
"""

import json
import os
import re
import pandas as pd
import numpy as np


# Maps CVSS text values to numeric encodings
ATTACK_VECTOR_MAP = {
    "NETWORK": 4, "ADJACENT": 3, "ADJACENT_NETWORK": 3,
    "LOCAL": 2, "PHYSICAL": 1,
}
ATTACK_COMPLEXITY_MAP = {"LOW": 2, "HIGH": 1}
PRIVILEGES_REQUIRED_MAP = {"NONE": 3, "LOW": 2, "HIGH": 1}
USER_INTERACTION_MAP = {"NONE": 2, "REQUIRED": 1}
SCOPE_MAP = {"CHANGED": 2, "UNCHANGED": 1}
IMPACT_MAP = {"HIGH": 3, "LOW": 2, "NONE": 1}

PRIORITY_MAP = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def cvss_score_to_priority(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def encode_metric(value: str, mapping: dict) -> int:
    return mapping.get((value or "").upper(), 0)


def extract_cwe_number(cwe_str: str) -> int:
    """Extract the numeric part of a CWE-NNN string."""
    if not cwe_str:
        return 0
    m = re.search(r"(\d+)", cwe_str)
    return int(m.group(1)) if m else 0


class NvdDataProcessor:
    FEATURE_COLUMNS = [
        "cvss_score",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "scope",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "cwe_number",
    ]
    TARGET_COLUMN = "priority"

    def load_from_directory(self, nvd_dir: str) -> pd.DataFrame:
        """Load all NVD JSON files from a directory into a combined DataFrame."""
        records = []
        for fname in os.listdir(nvd_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(nvd_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                items = data.get("vulnerabilities") or data.get("CVE_Items") or []
                for item in items:
                    row = self._extract_row(item)
                    if row:
                        records.append(row)
            except (json.JSONDecodeError, OSError, KeyError):
                continue

        if not records:
            raise ValueError(f"No valid CVE records found in {nvd_dir}")

        df = pd.DataFrame(records)
        df = self._clean(df)
        return df

    def get_feature_matrix(self, df: pd.DataFrame):
        """Return X (features) and y (encoded labels) arrays."""
        X = df[self.FEATURE_COLUMNS].values
        y = df[self.TARGET_COLUMN].map(PRIORITY_MAP).values
        return X, y

    def extract_single_finding_features(self, finding) -> list:
        """Extract feature vector from a NormalizedFinding ORM object."""
        score = finding.cvss_score or 0.0
        return [
            score,
            encode_metric(finding.attack_vector, ATTACK_VECTOR_MAP),
            encode_metric(finding.attack_complexity, ATTACK_COMPLEXITY_MAP),
            encode_metric(finding.privileges_required, PRIVILEGES_REQUIRED_MAP),
            encode_metric(finding.user_interaction, USER_INTERACTION_MAP),
            encode_metric(finding.scope, SCOPE_MAP),
            encode_metric(finding.confidentiality_impact, IMPACT_MAP),
            encode_metric(finding.integrity_impact, IMPACT_MAP),
            encode_metric(finding.availability_impact, IMPACT_MAP),
            extract_cwe_number(finding.cwe_id),
        ]

    def _extract_row(self, item: dict) -> dict | None:
        cve = item.get("cve", item)
        metrics = cve.get("metrics", {})

        cvss_data = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        )

        score = cvss_data.get("baseScore")
        if score is None:
            return None

        try:
            score = float(score)
        except (TypeError, ValueError):
            return None

        weaknesses = cve.get("weaknesses", [])
        cwe_str = ""
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_str = val
                    break
            if cwe_str:
                break

        return {
            "cve_id": cve.get("id", ""),
            "cvss_score": score,
            "attack_vector": cvss_data.get("attackVector", ""),
            "attack_complexity": cvss_data.get("attackComplexity", ""),
            "privileges_required": cvss_data.get("privilegesRequired", ""),
            "user_interaction": cvss_data.get("userInteraction", ""),
            "scope": cvss_data.get("scope", ""),
            "confidentiality_impact": cvss_data.get("confidentialityImpact", ""),
            "integrity_impact": cvss_data.get("integrityImpact", ""),
            "availability_impact": cvss_data.get("availabilityImpact", ""),
            "cwe_number": extract_cwe_number(cwe_str),
            "priority": cvss_score_to_priority(score),
        }

    def _clean(self, df: pd.DataFrame) -> pd.DataFrame:
        # Encode categorical columns
        for col, mapping in [
            ("attack_vector", ATTACK_VECTOR_MAP),
            ("attack_complexity", ATTACK_COMPLEXITY_MAP),
            ("privileges_required", PRIVILEGES_REQUIRED_MAP),
            ("user_interaction", USER_INTERACTION_MAP),
            ("scope", SCOPE_MAP),
            ("confidentiality_impact", IMPACT_MAP),
            ("integrity_impact", IMPACT_MAP),
            ("availability_impact", IMPACT_MAP),
        ]:
            if col in df.columns:
                df[col] = df[col].str.upper().map(mapping).fillna(0).astype(int)

        df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(0)
        df["cwe_number"] = pd.to_numeric(df["cwe_number"], errors="coerce").fillna(0).astype(int)
        df = df.dropna(subset=["priority"])
        return df

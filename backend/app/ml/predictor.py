"""
ML Predictor

Loads the trained Random Forest model and produces priority predictions
for NormalizedFinding records. Priority labels: Critical | High | Medium | Low
"""

import os
import json
import pickle
import numpy as np
from datetime import datetime
from flask import current_app
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.ml_prediction import MlPrediction
from app.ml.nvdtrans_processor import (
    PRIORITY_MAP,
    ATTACK_VECTOR_MAP,
    ATTACK_COMPLEXITY_MAP,
    PRIV_REQUIRED_MAP,
    USER_INTERACTION_MAP,
    SCOPE_MAP,
    IMPACT_MAP,
    _cwe_from_text,
)

REVERSE_PRIORITY = {v: k for k, v in PRIORITY_MAP.items()}

# Must match app.ml.model_trainer.FEATURE_COLUMNS exactly (order included).
# cvss_score is intentionally excluded — it is the source of the training label,
# so including it would be target leakage. See model_trainer.py for the rationale.
FEATURE_COLUMNS = [
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


def _encode(value: str | None, mapping: dict) -> int:
    return mapping.get((value or "").upper(), 0)


def _extract_cwe_number(cwe_id: str | None) -> int:
    if not cwe_id:
        return 0
    import re
    m = re.search(r"(\d+)", cwe_id)
    return int(m.group(1)) if m else 0


class VulnerabilityPredictor:
    _model = None
    _model_version = "unknown"

    def _load_model(self):
        if self._model is not None:
            return
        model_dir = current_app.config["ML_MODEL_PATH"]
        model_path = os.path.join(model_dir, "random_forest.pkl")
        meta_path = os.path.join(model_dir, "model_meta.json")

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. "
                "Run 'python -m app.ml.model_trainer' to train first."
            )
        from app.ml.random_forest import NumpyRandomForest  # noqa: F401
        with open(model_path, "rb") as f:
            self._model = pickle.load(f)
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            self._model_version = meta.get("model_version", "unknown")

    def _build_feature_vector(self, finding: NormalizedFinding) -> list:
        """Build the 9-element feature vector from a NormalizedFinding.

        Mirrors FEATURE_COLUMNS — CVSS sub-metrics + CWE, no raw cvss_score.
        """
        cwe_num = _extract_cwe_number(finding.cwe_id)

        # Fall back to keyword CWE if structured one missing
        if cwe_num == 0 and finding.title:
            cwe_num = _cwe_from_text(finding.title + " " + (finding.description or ""))

        return [
            _encode(finding.attack_vector,          ATTACK_VECTOR_MAP),
            _encode(finding.attack_complexity,      ATTACK_COMPLEXITY_MAP),
            _encode(finding.privileges_required,    PRIV_REQUIRED_MAP),
            _encode(finding.user_interaction,       USER_INTERACTION_MAP),
            _encode(finding.scope,                  SCOPE_MAP),
            _encode(finding.confidentiality_impact, IMPACT_MAP),
            _encode(finding.integrity_impact,       IMPACT_MAP),
            _encode(finding.availability_impact,    IMPACT_MAP),
            cwe_num,
        ]

    def predict_finding(self, finding: NormalizedFinding) -> MlPrediction:
        """Predict priority for a single finding and persist the result."""
        self._load_model()
        features = self._build_feature_vector(finding)
        X = np.array([features], dtype=float)

        pred_idx = int(self._model.predict(X)[0])
        proba = self._model.predict_proba(X)[0]

        # classes_ is sorted [0,1,2,3] → Low, Medium, High, Critical
        classes = self._model.classes_
        prob_map = {REVERSE_PRIORITY[int(c)]: float(p) for c, p in zip(classes, proba)}

        existing = finding.ml_prediction
        pred = existing if existing else MlPrediction(finding_id=finding.id)

        pred.predicted_priority = REVERSE_PRIORITY[pred_idx]
        pred.prob_low      = prob_map.get("Low",      0.0)
        pred.prob_medium   = prob_map.get("Medium",   0.0)
        pred.prob_high     = prob_map.get("High",     0.0)
        pred.prob_critical = prob_map.get("Critical", 0.0)
        pred.model_version = self._model_version
        pred.feature_vector = dict(zip(FEATURE_COLUMNS, features))
        pred.predicted_at = datetime.utcnow()

        db.session.add(pred)
        return pred

    def predict_all_unpredicted(self) -> int:
        """Run predictions for all findings that lack an ML prediction."""
        self._load_model()
        findings = (
            NormalizedFinding.query
            .outerjoin(MlPrediction, MlPrediction.finding_id == NormalizedFinding.id)
            .filter(MlPrediction.id.is_(None))
            .all()
        )
        for f in findings:
            self.predict_finding(f)
        db.session.commit()
        return len(findings)

    def model_info(self) -> dict:
        try:
            self._load_model()
            model_dir = current_app.config["ML_MODEL_PATH"]
            meta_path = os.path.join(model_dir, "model_meta.json")
            if os.path.exists(meta_path):
                with open(meta_path) as f:
                    return json.load(f)
        except FileNotFoundError:
            pass
        return {"status": "model not trained", "model_version": None}

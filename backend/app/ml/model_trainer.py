"""
Random Forest Model Trainer

Trains the priority classification model using NVD XML translation feed data.
Uses a pure numpy Random Forest implementation — no scikit-learn required.

Run as a standalone script:
  cd backend
  python -m app.ml.model_trainer
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter

# Ensure the backend package root is on the path
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.ml.nvdtrans_processor import load_nvdtrans_directory, PRIORITY_MAP
from app.ml.json_feed_processor import list_json_feeds, load_json_feeds_directory
from app.ml.random_forest import NumpyRandomForest


def load_training_data(nvd_dir: str):
    """Load the best available training source from nvd_dir.

    Prefers the structured NVD JSON 2.0 feeds (.json/.json.xz) — tens of
    thousands of cleanly-encoded CVSS-v3 rows — and falls back to the Spanish
    'nvdtrans' XML feed (regex-inferred, ~800 rows) only when no JSON is present.
    Returns (DataFrame, source_label).
    """
    if list_json_feeds(nvd_dir):
        print("[Trainer] Using NVD JSON 2.0 feeds (structured CVSS vectors).")
        return load_json_feeds_directory(nvd_dir), "nvd_json_v2"
    print("[Trainer] No JSON feeds found; falling back to nvdtrans XML.")
    return load_nvdtrans_directory(nvd_dir), "nvdtrans_xml"

REVERSE_PRIORITY = {v: k for k, v in PRIORITY_MAP.items()}
MODEL_VERSION = "2.0.0"

# NOTE: cvss_score is deliberately EXCLUDED from the features.
# The training label (`priority`) is derived directly from cvss_score, so feeding
# the score back in as an input is target leakage — the model would just relearn
# the severity-band thresholds (>=9 Critical, >=7 High, ...) and report a
# meaningless ~100% accuracy. Instead the model predicts the severity band from
# the underlying CVSS *vector* components (+ CWE), which is a genuine, non-trivial
# learning task and still works when a scanner reports a vector but no base score.
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

# Integer metric columns eligible for noise during augmentation
# (everything except the free-ranging cwe_number).
INT_METRIC_COLUMNS = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]


def _stratified_split_indices(y, test_size=0.2, random_state=42):
    """Return (train_idx, test_idx) stratified by class label."""
    rng = np.random.default_rng(random_state)
    train_idx, test_idx = [], []
    for cls in np.unique(y):
        cls_idx = np.where(y == cls)[0]
        rng.shuffle(cls_idx)
        n_test = max(1, int(len(cls_idx) * test_size))
        test_idx.extend(cls_idx[:n_test].tolist())
        train_idx.extend(cls_idx[n_test:].tolist())
    return np.array(train_idx), np.array(test_idx)


def _stratified_split(X, y, test_size=0.2, random_state=42):
    rng = np.random.default_rng(random_state)
    train_idx, test_idx = [], []
    for cls in np.unique(y):
        cls_idx = np.where(y == cls)[0]
        rng.shuffle(cls_idx)
        n_test = max(1, int(len(cls_idx) * test_size))
        test_idx.extend(cls_idx[:n_test].tolist())
        train_idx.extend(cls_idx[n_test:].tolist())
    return (X[train_idx], X[test_idx],
            y[train_idx], y[test_idx])


def _classification_report(y_true, y_pred, target_names):
    result = {}
    classes = sorted(set(y_true) | set(y_pred))
    for cls in classes:
        name = target_names[cls] if cls < len(target_names) else str(cls)
        tp = np.sum((y_pred == cls) & (y_true == cls))
        fp = np.sum((y_pred == cls) & (y_true != cls))
        fn = np.sum((y_pred != cls) & (y_true == cls))
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        result[name] = {
            "precision": float(prec),
            "recall": float(rec),
            "f1-score": float(f1),
            "support": int(np.sum(y_true == cls)),
        }
    accuracy = float(np.sum(y_true == y_pred) / len(y_true))
    result["accuracy"] = accuracy
    return result


def _confusion_matrix(y_true, y_pred, n_classes):
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t][p] += 1
    return cm.tolist()


def augment_with_synthetic(df: pd.DataFrame, target_per_class: int = 1500) -> pd.DataFrame:
    """Over-sample minority classes with small noise."""
    rng = np.random.default_rng(42)
    bands = {"Critical": (9.0, 10.0), "High": (7.0, 8.9),
             "Medium": (4.0, 6.9), "Low": (0.1, 3.9)}
    int_cols = INT_METRIC_COLUMNS  # CVSS sub-metrics (cwe_number jittered separately)
    int_bounds = {
        "attack_vector": (0, 4), "attack_complexity": (0, 2),
        "privileges_required": (0, 3), "user_interaction": (0, 2),
        "scope": (0, 2), "confidentiality_impact": (0, 3),
        "integrity_impact": (0, 3), "availability_impact": (0, 3),
    }

    augmented_parts = [df]
    for priority in ["Critical", "High", "Medium", "Low"]:
        class_df = df[df["priority"] == priority]
        n_have = len(class_df)
        n_need = target_per_class - n_have
        if n_need <= 0:
            continue

        # Sample with replacement from the real class samples
        src_idx = rng.choice(len(class_df), size=n_need, replace=True)
        synthetic = class_df.iloc[src_idx].copy().reset_index(drop=True)

        # Add small noise to integer metric columns
        for col in int_cols:
            lo, hi = int_bounds[col]
            noise = rng.integers(-1, 2, size=n_need)
            synthetic[col] = (synthetic[col].values + noise).clip(lo, hi)

        # Jitter CVSS score within the priority band (kept only for reporting/
        # traceability; cvss_score is NOT a model feature, see FEATURE_COLUMNS).
        if "cvss_score" in synthetic.columns:
            lo_s, hi_s = bands[priority]
            score_noise = rng.uniform(-0.3, 0.3, size=n_need)
            synthetic["cvss_score"] = (
                synthetic["cvss_score"].values + score_noise
            ).clip(lo_s, hi_s)

        augmented_parts.append(synthetic)

    combined = pd.concat(augmented_parts, ignore_index=True)
    shuffle_idx = rng.permutation(len(combined))
    return combined.iloc[shuffle_idx].reset_index(drop=True)


class ModelTrainer:
    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)

    def train(self, nvd_dir: str) -> dict:
        print(f"\n[Trainer] Loading NVD data from {nvd_dir} ...")
        df, data_source = load_training_data(nvd_dir)
        self._data_source = data_source
        print(f"[Trainer] Raw real records: {len(df):,}  (source: {data_source})")

        # --- Split the REAL data first ----------------------------------------
        # Augmenting before the split would copy (with replacement) the same real
        # records into both train and test, leaking near-duplicates across the
        # split and inflating accuracy. So we split first, then synthesise ONLY
        # from the training rows and evaluate on untouched real test rows.
        y_real = df["priority"].map(PRIORITY_MAP).values
        train_idx, test_idx = _stratified_split_indices(y_real, test_size=0.2)
        train_df = df.iloc[train_idx].reset_index(drop=True)
        test_df = df.iloc[test_idx].reset_index(drop=True)
        print(f"[Trainer] Real split -> train {len(train_df):,} / test {len(test_df):,}")

        # Balance the training set only (test stays real + untouched).
        train_df = augment_with_synthetic(train_df, target_per_class=1500)
        print(f"[Trainer] Train after augmentation: {len(train_df):,} records")
        for p in ["Critical", "High", "Medium", "Low"]:
            n = (train_df["priority"] == p).sum()
            print(f"  {p:10s}: {n:,}")

        X_train = train_df[FEATURE_COLUMNS].values.astype(float)
        y_train = train_df["priority"].map(PRIORITY_MAP).values
        X_test = test_df[FEATURE_COLUMNS].values.astype(float)
        y_test = test_df["priority"].map(PRIORITY_MAP).values

        print(f"\n[Trainer] Training Random Forest on {len(X_train):,} synthetic-"
              f"balanced samples; evaluating on {len(X_test):,} real held-out rows ...")

        model = NumpyRandomForest(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features="sqrt",
            random_state=42,
        )
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        target_names = ["Low", "Medium", "High", "Critical"]
        report = _classification_report(y_test, y_pred, target_names)
        cm = _confusion_matrix(y_test, y_pred, n_classes=4)

        importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_.tolist()))

        # Macro-averaged F1 — the honest headline metric under class imbalance
        # (plain accuracy is dominated by the Medium majority class).
        per_class_f1 = [report[n]["f1-score"] for n in target_names if n in report]
        macro_f1 = float(np.mean(per_class_f1)) if per_class_f1 else 0.0

        metrics = {
            "model_version": MODEL_VERSION,
            "trained_at": datetime.utcnow().isoformat(),
            "training_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "data_source": getattr(self, "_data_source", "unknown"),
            "evaluation": "real held-out NVD records (no synthetic data in test set)",
            "accuracy": float(report["accuracy"]),
            "macro_f1": macro_f1,
            "classification_report": report,
            "confusion_matrix": cm,
            "feature_importances": importances,
            "feature_columns": FEATURE_COLUMNS,
            "implementation": "numpy_random_forest",
        }

        self._save(model, metrics)
        return metrics

    def _save(self, model: NumpyRandomForest, metrics: dict) -> None:
        model_path = os.path.join(self.model_dir, "random_forest.pkl")
        meta_path  = os.path.join(self.model_dir, "model_meta.json")

        model.save(model_path)
        with open(meta_path, "w") as f:
            json.dump(metrics, f, indent=2)

        print(f"\n[Trainer] Model saved  -> {model_path}")
        print(f"[Trainer] Accuracy     : {metrics['accuracy']:.4f}")
        print("\nFeature importances:")
        feat_imps = metrics["feature_importances"]
        for feat, imp in sorted(feat_imps.items(), key=lambda x: x[1], reverse=True):
            bar = "#" * int(imp * 40)
            print(f"  {feat:28s} {imp:.4f}  {bar}")


if __name__ == "__main__":
    # __file__ = FYP/backend/app/ml/model_trainer.py → go up 4 levels to FYP root
    base_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    nvd_data_dir  = os.path.join(base_dir, "ml_data", "nvd")
    model_out_dir = os.path.join(base_dir, "ml_data", "models")
    os.makedirs(model_out_dir, exist_ok=True)

    if not os.path.isdir(nvd_data_dir) or not any(
        f.endswith(".xml") for f in os.listdir(nvd_data_dir)
    ):
        print(f"ERROR: No XML files in {nvd_data_dir}")
        print("Run python setup_nvd_data.py first.")
        sys.exit(1)

    trainer = ModelTrainer(model_out_dir)
    metrics = trainer.train(nvd_data_dir)
    importances = metrics["feature_importances"]

    print("\n=== Training Complete ===")
    summary = {k: v for k, v in metrics.items()
               if k not in ("classification_report", "confusion_matrix", "feature_importances")}
    print(json.dumps(summary, indent=2))

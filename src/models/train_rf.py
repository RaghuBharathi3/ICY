"""
train_rf.py
────────────────────────────────────────────────────────────────────────────────
Phase 3 — Random Forest Training
Skill references: scikit-learn, ml-pipeline-workflow, mlops-engineer

Runs 3 experiments as defined in the master prompt:
  Exp 1 — Baseline: raw features, no SMOTE
  Exp 2 — Engineered: custom features + SMOTE
  Exp 3 — Ensemble: engineered + IF anomaly layer (see ensemble.py)

Saves:
  artifacts/models/rf_model.pkl
  artifacts/reports/baseline.json
  artifacts/reports/engineered.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)

logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path("artifacts")
MODELS_DIR = ARTIFACTS_DIR / "models"
REPORTS_DIR = ARTIFACTS_DIR / "reports"


def _compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    label: str,
) -> dict:
    """Compute F1, ROC-AUC, confusion matrix, FP rate."""
    f1 = f1_score(y_true, y_pred, average="binary")
    roc = roc_auc_score(y_true, y_prob)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metrics = {
        "experiment": label,
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc), 4),
        "fp_rate": round(float(fp_rate), 4),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp),
        },
        "classification_report": classification_report(y_true, y_pred, output_dict=True),
    }
    logger.info(f"[{label}] F1={f1:.4f} | ROC-AUC={roc:.4f} | FP Rate={fp_rate:.4f}")
    return metrics


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    experiment_name: str,
    n_estimators: int = 100,
    random_state: int = 42,
) -> tuple[RandomForestClassifier, dict]:
    """
    Train RF, evaluate, return (model, metrics_dict).
    Hyperparameters are locked — do not change without explicit instruction.
    """
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",   # handles imbalance at model level
        random_state=random_state,
        n_jobs=-1,
    )
    logger.info(f"Training Random Forest [{experiment_name}] on {X_train.shape[0]} samples...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    metrics = _compute_metrics(y_test, y_pred, y_prob, experiment_name)

    return model, metrics


def save_model(model: RandomForestClassifier, name: str = "rf_model") -> Path:
    """Save model artifact to artifacts/models/."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    path = MODELS_DIR / f"{name}.pkl"
    joblib.dump(model, path)
    logger.info(f"Model saved -> {path}")
    return path


def save_report(metrics: dict, name: str) -> Path:
    """Save metrics JSON to artifacts/reports/."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Report saved -> {path}")
    return path


def run_experiment_1_baseline(
    data_dir: str | Path = "data/raw",
    extra_dirs: list | None = None,
) -> dict:
    """
    Experiment 1: Baseline — raw CICIDS2017 columns, no feature engineering, no SMOTE.
    Establishes the performance floor to prove our engineering adds value.
    """
    from src.pipeline.preprocessor import full_pipeline
    logger.info("=" * 60)
    logger.info("EXPERIMENT 1 -- BASELINE (raw features, no SMOTE)")
    logger.info("=" * 60)
    data = full_pipeline(data_dir, apply_engineering=False, use_smote=False, extra_dirs=extra_dirs)
    model, metrics = train_random_forest(
        data["X_train"], data["y_train"],
        data["X_test"], data["y_test"],
        experiment_name="baseline",
    )
    save_model(model, "rf_baseline")
    save_report(metrics, "baseline")
    return metrics


def run_experiment_2_engineered(
    data_dir: str | Path = "data/raw",
    extra_dirs: list | None = None,
) -> tuple[RandomForestClassifier, dict]:
    """
    Experiment 2: Engineered — custom 7 features + SMOTE.
    Proves feature engineering improves detection.
    """
    from src.pipeline.preprocessor import full_pipeline
    logger.info("=" * 60)
    logger.info("EXPERIMENT 2 -- ENGINEERED FEATURES + SMOTE")
    logger.info("=" * 60)
    data = full_pipeline(data_dir, apply_engineering=True, use_smote=True, extra_dirs=extra_dirs)
    model, metrics = train_random_forest(
        data["X_train"], data["y_train"],
        data["X_test"], data["y_test"],
        experiment_name="engineered",
    )
    save_model(model, "rf_model")   # this becomes the production model
    save_report(metrics, "engineered")
    return model, metrics

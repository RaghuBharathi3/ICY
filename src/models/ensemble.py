"""
ensemble.py
────────────────────────────────────────────────────────────────────────────────
Phase 3 — Experiment 3: RF + IF Ensemble Decision Logic
Skill references: scikit-learn, ml-pipeline-workflow

Decision logic (from master prompt — do NOT change):
  if RF = Attack              → final = "ATTACK"
  if RF = Normal AND IF < 0   → final = "SUSPICIOUS"  (anomalous but not classified)
  if RF = Normal AND IF >= 0  → final = "NORMAL"

This gives 3 output states, preserving the binary label scheme while
adding a warning layer for borderline traffic.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import f1_score, roc_auc_score, confusion_matrix

logger = logging.getLogger(__name__)

MODELS_DIR = Path("artifacts/models")
REPORTS_DIR = Path("artifacts/reports")

# Decision labels
ATTACK = "ATTACK"
SUSPICIOUS = "SUSPICIOUS"
NORMAL = "NORMAL"


class EnsemblePredictor:
    """Combines RF (supervised) + IF (anomaly) with the locked decision logic."""

    def __init__(self, rf_model_path: str | Path, if_model_path: str | Path):
        self.rf = joblib.load(rf_model_path)
        self.if_ = joblib.load(if_model_path)
        logger.info("EnsemblePredictor loaded: RF + IF models ready")

    def predict(self, X: np.ndarray) -> list[str]:
        """
        Return ensemble decision for each sample.
        Output: list of "ATTACK" | "SUSPICIOUS" | "NORMAL"
        """
        rf_preds = self.rf.predict(X)           # 0 = Normal, 1 = Attack
        rf_probs = self.rf.predict_proba(X)[:, 1]  # P(Attack)
        if_scores = self.if_.decision_function(X)  # < 0 = anomalous

        decisions = []
        for rf_pred, if_score in zip(rf_preds, if_scores):
            if rf_pred == 1:
                decisions.append(ATTACK)
            elif if_score < 0:
                decisions.append(SUSPICIOUS)
            else:
                decisions.append(NORMAL)
        return decisions

    def predict_with_scores(self, X: np.ndarray) -> list[dict]:
        """Return detailed prediction dict for each sample (used by API)."""
        rf_preds = self.rf.predict(X)
        rf_probs = self.rf.predict_proba(X)[:, 1]
        if_scores = self.if_.decision_function(X)
        decisions = self.predict(X)

        results = []
        for i in range(len(X)):
            results.append({
                "decision": decisions[i],
                "rf_prediction": int(rf_preds[i]),
                "rf_confidence": round(float(rf_probs[i]), 4),
                "if_anomaly_score": round(float(if_scores[i]), 4),
                "is_anomalous": bool(if_scores[i] < 0),
            })
        return results


def run_experiment_3_ensemble(data_dir: str | Path = "data/raw", rf_model=None) -> dict:
    """
    Experiment 3: Ensemble evaluation on test set.
    Uses production models (rf_model.pkl + if_model.pkl).
    """
    from src.pipeline.preprocessor import full_pipeline
    logger.info("═" * 60)
    logger.info("EXPERIMENT 3 — RF + IF ENSEMBLE")
    logger.info("═" * 60)

    data = full_pipeline(data_dir, apply_engineering=True, use_smote=False)
    X_train, X_test, y_test = data["X_train"], data["X_test"], data["y_test"]

    # Train & save Isolation Forest on training features
    from src.models.train_if import train_isolation_forest, save_if_model
    if_model = train_isolation_forest(X_train)
    save_if_model(if_model)

    # Save in-memory RF if provided (avoid reloading from disk)
    if rf_model is not None:
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        import joblib as _jl
        _jl.dump(rf_model, MODELS_DIR / "rf_model.pkl")
        logger.info("RF model saved from memory for ensemble use.")

    predictor = EnsemblePredictor(
        rf_model_path=MODELS_DIR / "rf_model.pkl",
        if_model_path=MODELS_DIR / "if_model.pkl",
    )

    decisions = predictor.predict(X_test)

    # Convert 3-way decisions back to binary for metric computation
    # ATTACK → 1, SUSPICIOUS → 1 (conservative), NORMAL → 0
    y_pred_binary = [1 if d in (ATTACK, SUSPICIOUS) else 0 for d in decisions]
    y_pred_binary = np.array(y_pred_binary)

    rf_probs = predictor.rf.predict_proba(X_test)[:, 1]
    f1 = f1_score(y_test, y_pred_binary, average="binary")
    roc = roc_auc_score(y_test, rf_probs)
    cm = confusion_matrix(y_test, y_pred_binary)
    tn, fp, fn, tp = cm.ravel()
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metrics = {
        "experiment": "ensemble",
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc), 4),
        "fp_rate": round(float(fp_rate), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "decision_counts": {
            ATTACK: decisions.count(ATTACK),
            SUSPICIOUS: decisions.count(SUSPICIOUS),
            NORMAL: decisions.count(NORMAL),
        },
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPORTS_DIR / "ensemble.json", "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Ensemble F1={f1:.4f} | ROC-AUC={roc:.4f} | FP Rate={fp_rate:.4f}")
    logger.info(f"Decisions: {metrics['decision_counts']}")
    return metrics

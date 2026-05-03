"""
predictor.py
────────────────────────────────────────────────────────────────────────────────
Phase 5 — Inference Engine
Loads trained models, runs prediction + SHAP explanation on incoming feature rows.
Used by both the watcher pipeline and the FastAPI backend.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

MODELS_DIR = Path("artifacts/models")


@dataclass
class FlowRecord:
    """Represents a single analyzed network flow."""
    flow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    src_ip: str = "unknown"
    dst_ip: str = "unknown"
    decision: str = "UNKNOWN"          # ATTACK | SUSPICIOUS | NORMAL
    rf_confidence: float = 0.0
    if_anomaly_score: float = 0.0
    is_anomalous: bool = False
    top_features: list = field(default_factory=list)   # SHAP top-5
    raw_features: dict = field(default_factory=dict)


class Predictor:
    """
    Central inference engine.
    Loads RF + IF models once and serves predictions.
    Used by the watch folder pipeline and API.
    """

    def __init__(
        self,
        rf_path: str | Path = MODELS_DIR / "rf_model.pkl",
        if_path: str | Path = MODELS_DIR / "if_model.pkl",
        feature_cols: Optional[list[str]] = None,
    ):
        self.rf = joblib.load(rf_path)
        self.if_ = joblib.load(if_path)
        self.feature_cols = feature_cols or []
        self._shap_explainer = None
        logger.info("Predictor initialized — RF + IF loaded")

    def _get_shap_explainer(self):
        """Lazy-load SHAP explainer to avoid startup overhead."""
        if self._shap_explainer is None and self.feature_cols:
            from src.explainability.shap_explainer import SHAPExplainer
            self._shap_explainer = SHAPExplainer(
                model_path=MODELS_DIR / "rf_model.pkl",
                feature_cols=self.feature_cols,
            )
        return self._shap_explainer

    def predict_single(
        self,
        x: np.ndarray,
        src_ip: str = "unknown",
        dst_ip: str = "unknown",
        raw_features: Optional[dict] = None,
        explain: bool = True,
    ) -> FlowRecord:
        """Run full prediction pipeline for a single flow vector."""
        if x.ndim == 1:
            x = x.reshape(1, -1)

        rf_pred = self.rf.predict(x)[0]
        rf_prob = float(self.rf.predict_proba(x)[0, 1])
        if_score = float(self.if_.decision_function(x)[0])

        # Locked decision logic from master prompt
        if rf_pred == 1:
            decision = "ATTACK"
        elif if_score < 0:
            decision = "SUSPICIOUS"
        else:
            decision = "NORMAL"

        # SHAP explanation — skipped during bulk inference for speed
        top_features = []
        if explain:
            explainer = self._get_shap_explainer()
            if explainer:
                try:
                    top_features = explainer.explain_single(x)
                except Exception as e:
                    logger.warning(f"SHAP explanation failed: {e}")

        return FlowRecord(
            src_ip=src_ip,
            dst_ip=dst_ip,
            decision=decision,
            rf_confidence=round(rf_prob, 4),
            if_anomaly_score=round(if_score, 4),
            is_anomalous=if_score < 0,
            top_features=top_features,
            raw_features=raw_features or {},
        )

    def predict_batch(self, X: np.ndarray, explain: bool = False) -> list[FlowRecord]:
        """Fast vectorised batch prediction. SHAP disabled by default for speed."""
        rf_preds = self.rf.predict(X)
        rf_probs = self.rf.predict_proba(X)[:, 1]
        if_scores = self.if_.decision_function(X)

        records = []
        for i in range(len(X)):
            if rf_preds[i] == 1:
                decision = "ATTACK"
            elif if_scores[i] < 0:
                decision = "SUSPICIOUS"
            else:
                decision = "NORMAL"

            top_features = []
            if explain:
                explainer = self._get_shap_explainer()
                if explainer:
                    try:
                        top_features = explainer.explain_single(X[i:i+1])
                    except Exception as e:
                        logger.warning(f"SHAP failed row {i}: {e}")

            records.append(FlowRecord(
                decision=decision,
                rf_confidence=round(float(rf_probs[i]), 4),
                if_anomaly_score=round(float(if_scores[i]), 4),
                is_anomalous=bool(if_scores[i] < 0),
                top_features=top_features,
            ))
        return records
